import logging
import logging.config
import threading
import time
import os
import sys
import base64
import json
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed, ThreadPoolExecutor
import re
from dotenv import load_dotenv

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import configuration
try:
    from config import LOGGING
    
    # Configure logging
    logging.config.dictConfig(LOGGING)
    
    # Import local modules
    import gmail_utils
    import email_cache
    import threat_intel
    from phishing_detector import PhishingDetector
    import heuristics
    from intelligence.heuristics import resolve_brand
    
    # Initialize modules
    phishing_detector = PhishingDetector()
    
except ImportError as e:
    logging.error(f"Failed to import required modules in background_sync.py: {e}")
    raise

# Import remaining modules
try:
    from auth_checks import verify_message_auth
    from email_cache import get_all_msg_ids, get_cached_email
    
    logger = logging.getLogger("background_sync")
    try:
        phishing_detector.load_model("./phishing_mail_detect_model")
    except Exception as e:
        logger.debug(f"[DETECTOR] model load failed or model path missing: {e}")
    
    # Initialize sync status
    sync_status = {"running": False, "last_sync": None, "stats": {}}
    
    # Load environment variables
    load_dotenv()
    
except ImportError as e:
    logging.error(f"Failed to import additional modules in background_sync.py: {e}")
    raise

SYNC_MAX_FETCH_RESULTS = int(os.getenv("SYNC_MAX_FETCH_RESULTS", os.getenv("MAX_FETCH_RESULTS", "-1")))
SYNC_PARALLELISM = int(os.getenv("SYNC_PARALLELISM", "6"))  # Increased to 6 for massive email volumes
SYNC_BACKOFF_BASE = float(os.getenv("SYNC_BACKOFF_BASE", "2.0"))
SYNC_BACKOFF_MAX = float(os.getenv("SYNC_BACKOFF_MAX", "60.0"))

# Concurrent processing settings
CONCURRENT_FETCHING_ENABLED = os.getenv("CONCURRENT_FETCHING_ENABLED", "true").lower() in ("true", "1", "yes")
FETCH_QUEUE_SIZE = int(os.getenv("FETCH_QUEUE_SIZE", "1000"))  # Max emails in fetch queue
ANALYSIS_WORKERS = int(os.getenv("ANALYSIS_WORKERS", "4"))  # Number of analysis worker threads
FETCH_BATCH_SIZE = int(os.getenv("FETCH_BATCH_SIZE", "50"))  # Emails to fetch at once

# Incremental sync settings
SYNC_BATCH_SIZE = int(os.getenv("SYNC_BATCH_SIZE", "100"))  # Process emails in batches of 100
SYNC_MAX_INCREMENTAL_BATCHES = int(os.getenv("SYNC_MAX_INCREMENTAL_BATCHES", "10"))  # Max batches per incremental run
SYNC_STATE_FILE = os.path.join(os.path.dirname(__file__), "cache", "sync_state.json")

# Database batching settings
WAIT_TILL_FEED_DATABASE = int(os.getenv("WAIT_TILL_FEED_DATABASE", "1"))  # Accumulate emails before batch write

# Auto-optimization settings
AUTO_OPTIMIZE_ENABLED = os.getenv("AUTO_OPTIMIZE_ENABLED", "true").lower() in ("true", "1", "yes")
AUTO_OPTIMIZE_CONFIG_FILE = os.path.join(os.path.dirname(__file__), "cache", "sync_optimization.json")

# Auto-optimization classes and functions
class SyncOptimizer:
    """
    Rule-based auto-optimizer for sync performance.

    This class implements intelligent performance tuning for the email sync system
    by monitoring sync metrics and automatically adjusting parameters like batch sizes,
    parallelism, and database batching for optimal throughput.

    Features:
    - Historical performance tracking
    - Rule-based parameter optimization
    - Persistent learning across restarts
    - Safe bounds checking to prevent instability
    """

    def __init__(self):
        """
        Initialize the sync optimizer.

        Loads previously learned optimal settings from disk and prepares
        for performance monitoring and automatic adjustments.
        """
        self.config_file = AUTO_OPTIMIZE_CONFIG_FILE
        self.performance_history = []
        self.optimal_settings = self._load_optimal_settings()
        self.max_history = 10  # Keep last 10 sync runs

    def _load_optimal_settings(self):
        """Load previously learned optimal settings"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"[AUTO_OPT] Failed to load optimal settings: {e}")

        # Default optimal settings
        return {
            "batch_size": 100,
            "parallelism": 6,
            "db_batch_size": 10,
            "last_updated": None,
            "performance_score": 0.0
        }

    def _save_optimal_settings(self):
        """Save learned optimal settings"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(self.optimal_settings, f, indent=2)
        except Exception as e:
            logger.warning(f"[AUTO_OPT] Failed to save optimal settings: {e}")

    def record_sync_performance(self, stats):
        """Record sync performance metrics"""
        if not stats:
            return

        # Extract key metrics
        duration = stats.get("duration_sec", 0)
        processed = stats.get("processed", 0)
        failures = stats.get("failures", 0)

        if duration <= 0 or processed <= 0:
            return

        # Calculate performance metrics
        throughput = processed / duration  # emails/second
        error_rate = failures / (processed + failures) if (processed + failures) > 0 else 0
        success_rate = processed / (processed + failures) if (processed + failures) > 0 else 0

        performance_entry = {
            "timestamp": time.time(),
            "duration": duration,
            "processed": processed,
            "failures": failures,
            "throughput": throughput,
            "error_rate": error_rate,
            "success_rate": success_rate,
            "batch_size": SYNC_BATCH_SIZE,
            "parallelism": SYNC_PARALLELISM,
            "db_batch_size": WAIT_TILL_FEED_DATABASE
        }

        self.performance_history.append(performance_entry)

        # Keep only recent history
        if len(self.performance_history) > self.max_history:
            self.performance_history = self.performance_history[-self.max_history:]

        # Update optimal settings based on performance
        self._update_optimal_settings()

    def _update_optimal_settings(self):
        """Update optimal settings based on performance history"""
        if len(self.performance_history) < 3:
            return  # Need at least 3 runs for meaningful analysis

        # Calculate average performance
        recent_runs = self.performance_history[-5:]  # Last 5 runs
        avg_throughput = sum(run["throughput"] for run in recent_runs) / len(recent_runs)
        avg_error_rate = sum(run["error_rate"] for run in recent_runs) / len(recent_runs)
        avg_success_rate = sum(run["success_rate"] for run in recent_runs) / len(recent_runs)

        # Rule-based optimization logic
        new_settings = self.optimal_settings.copy()

        # Optimize batch size based on throughput
        if avg_throughput > 5:  # Good throughput
            new_settings["batch_size"] = min(new_settings["batch_size"] + 20, 300)
        elif avg_throughput < 2:  # Poor throughput
            new_settings["batch_size"] = max(new_settings["batch_size"] - 20, 50)

        # Optimize parallelism based on error rate
        if avg_error_rate < 0.05 and avg_success_rate > 0.95:  # Low errors, high success
            new_settings["parallelism"] = min(new_settings["parallelism"] + 1, 12)
        elif avg_error_rate > 0.15:  # High error rate
            new_settings["parallelism"] = max(new_settings["parallelism"] - 1, 2)

        # Optimize DB batch size based on overall performance
        performance_score = (avg_throughput * 0.4) + (avg_success_rate * 0.4) + ((1 - avg_error_rate) * 0.2)

        if performance_score > self.optimal_settings.get("performance_score", 0):
            # Better performance - increase DB batching for efficiency
            new_settings["db_batch_size"] = min(new_settings["db_batch_size"] + 5, 50)
            new_settings["performance_score"] = performance_score
        elif performance_score < self.optimal_settings.get("performance_score", 0) * 0.8:
            # Significantly worse - reduce batching
            new_settings["db_batch_size"] = max(new_settings["db_batch_size"] - 5, 5)

        # Update if settings changed
        if (new_settings["batch_size"] != self.optimal_settings["batch_size"] or
            new_settings["parallelism"] != self.optimal_settings["parallelism"] or
            new_settings["db_batch_size"] != self.optimal_settings["db_batch_size"]):

            new_settings["last_updated"] = time.time()
            self.optimal_settings = new_settings
            self._save_optimal_settings()

            logger.info(f"[AUTO_OPT] Updated optimal settings: batch_size={new_settings['batch_size']}, "
                       f"parallelism={new_settings['parallelism']}, db_batch_size={new_settings['db_batch_size']}")

    def get_optimal_settings(self):
        """Get current optimal settings"""
        return self.optimal_settings.copy()

    def should_apply_optimization(self):
        """Check if we should apply auto-optimized settings"""
        if not AUTO_OPTIMIZE_ENABLED:
            return False

        # Apply if we have enough performance history and recent updates
        if len(self.performance_history) < 3:
            return False

        last_update = self.optimal_settings.get("last_updated")
        if not last_update:
            return True

        # Re-apply if settings are older than 1 hour
        return (time.time() - last_update) > 3600

# Global optimizer instance
sync_optimizer = SyncOptimizer()

os.environ.setdefault("INTEL_MAX_PER_EMAIL", os.getenv("INTEL_MAX_PER_EMAIL", "10"))

# ============================================================================

def _safe_predict(text: str):
    try:
        return phishing_detector.predict(text)
    except Exception as e:
        logger.exception("[DETECTOR] model predict failed: %s", e)
        return {"label": "safe", "score": 0.0, "explanation": ""}


def process_single_email(item):
    """
    Process a single email through the complete phishing analysis pipeline.

    This function performs comprehensive email analysis including:
    - Whitelist checking for trusted senders
    - URL extraction and link analysis
    - Early heuristic analysis for empty emails
    - Machine learning phishing detection
    - Advanced heuristics scoring
    - Email authentication verification (SPF, DKIM, DMARC)
    - Threat intelligence enrichment
    - Brand/domain analysis
    - Manual override handling

    Args:
        item (dict): Email data dictionary containing:
            - id/msg_id: Gmail message ID
            - subject: Email subject line
            - sender: Sender email address
            - body: Email body text
            - html_body: HTML content if available
            - raw: Base64-encoded raw email data
            - urls: List of extracted URLs
            - attachments: List of attachment metadata

    Returns:
        dict: Analysis results containing:
            - email_data: Complete email record for database storage
            - label: Final phishing classification ('safe', 'phish', 'maybephish')
            - score: Confidence score (0.0 to 1.0)
            - intel_flags: Number of threat intelligence hits
            - impersonation_hits: Number of impersonation attempts detected

    Note:
        This function is designed for batch processing and returns data
        for database insertion rather than caching directly.
    """
    load_dotenv()
    strict_mode = os.getenv("STRICT_MODEL_ONLY", "false").lower() in ("true", "1", "yes")

    msg_id = item.get("id") or item.get("msg_id")
    subject = item.get("subject", "")
    sender = item.get("from", "") or item.get("sender", "")
    date = item.get("date", "")
    snippet = item.get("snippet", "")
    body = item.get("body", "")
    html_body = item.get("html_body", "")
    raw_data = item.get("raw", "")
    internal_date = item.get("internal_date", 0)
    urls = item.get("urls", []) or []
    attachments = item.get("attachments", []) or []

    combined_text = f"{subject}. {body or ''}".strip()

    # DEBUG: Log that we're processing this email
    logger.info(f"[SYNC] Processing email {msg_id[:8]}...")

    # Check whitelist - return email data for batching instead of caching directly
    try:
        wl = heuristics._get_whitelist_emails()
        sender_addr = ""
        m = re.search(r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+)", sender or "")
        if m:
            sender_addr = m.group(1).lower()
        if sender_addr and sender_addr in wl:
            label = "safe"
            score = 0.0
            explanation = "Sender is whitelisted. Skipping phishing analysis."
            extra_payload = {"risk_links": [], "urls": urls, "attachments": attachments}
            logger.debug(f"[DEBUG] Whitelisted email {msg_id[:8]} - will be batched")
            # Return email data for batching instead of caching directly
            return {
                "email_data": {
                    "msg_id": msg_id,
                    "subject": subject,
                    "sender": sender,
                    "date": date,
                    "snippet": snippet,
                    "body": body,
                    "raw": raw_data,
                    "prediction_label": label,
                    "prediction_score": score,
                    "explanation": explanation,
                    "html_body": html_body or "",
                    "internal_date": internal_date,
                    "extra": extra_payload
                },
                "label": label,
                "score": score,
                "intel_flags": 0,
                "impersonation_hits": 0
            }
    except Exception:
        logger.exception("[WHITELIST] check failed for %s", msg_id)

    # ------------------------------------------------------------
    # RESTORE URL EXTRACTION IF MISSING (due to recheck using cache)
    # ------------------------------------------------------------
    # If cached item lacks 'urls' (or urls empty) but we have raw_data, re-extract bodies and links
    if not urls and raw_data:
        try:
            raw_bytes = base64.urlsafe_b64decode(raw_data.encode("utf-8"))
            text_body2, html_body2 = gmail_utils.extract_bodies_from_mime(raw_bytes)

            if html_body2:
                try:
                    cleaned_text, urls = gmail_utils.clean_html_for_text(html_body2)
                    html_body = html_body2
                    body = cleaned_text
                    combined_text = f"{subject}. {body or ''}".strip()
                except Exception:
                    # fallback: set html_body but leave urls empty if extraction failed
                    html_body = html_body2

            elif text_body2:
                try:
                    cleaned_text, urls = gmail_utils.clean_html_for_text(text_body2)
                    body = cleaned_text
                    combined_text = f"{subject}. {body or ''}".strip()
                except Exception:
                    body = text_body2
        except Exception:
            # best-effort only; do not block processing on failure
            pass

    # ------------------------------------------------------------
    # EARLY ANALYSIS USING heuristics.analyze_email_links_and_content
    # Skip model + heuristics if email has no subject/body
    # ------------------------------------------------------------
    try:
        early = heuristics.analyze_email_links_and_content(
            msg_id,
            subject or "",
            body or "",
            html_body or "",
            sender or ""
        )
        early_expl = (early.get("explanation") or "").strip() or ""
        # check exact phrase (case-insensitive) but match against user's required text
        if early_expl.upper().startswith("NO TEXT DETECTED"):
            label = early.get("label", "safe")
            score = float(early.get("score", 0.0))
            explanation = early.get("explanation", "")
            risk_links = early.get("risk_links", [])
            urls = early.get("urls", [])
            heur_adj = 0.0  # heuristics skipped

            # Return email data for batching instead of caching directly
            extra_payload = {"risk_links": risk_links, "urls": urls, "attachments": attachments}
            logger.debug(f"[DEBUG] Early analysis email {msg_id[:8]} - will be batched")
            return {
                "email_data": {
                    "msg_id": msg_id,
                    "subject": subject,
                    "sender": sender,
                    "date": date,
                    "snippet": snippet,
                    "body": body,
                    "raw": raw_data,
                    "prediction_label": label,
                    "prediction_score": score,
                    "explanation": explanation,
                    "html_body": html_body or "",
                    "internal_date": internal_date,
                    "extra": extra_payload
                },
                "label": label,
                "score": score,
                "intel_flags": 0,
                "impersonation_hits": 0
            }
    except Exception as e:
        logger.exception("[EARLY_ANALYZER] failure: %s", e)


    # --- REAL EMPTY CHECK (fix Unknown empty emails) ---
    if not subject.strip() and not body.strip() and not html_body.strip():
        label = "safe"
        score = 0.0
        explanation = "No content detected. Email treated as safe."
        extra_payload = {"risk_links": [], "urls": urls, "attachments": attachments}
        logger.debug(f"[DEBUG] Empty email {msg_id[:8]} - will be batched")
        # Return email data for batching instead of caching directly
        return {
            "email_data": {
                "msg_id": msg_id,
                "subject": subject,
                "sender": sender,
                "date": date,
                "snippet": snippet,
                "body": body,
                "raw": raw_data,
                "prediction_label": label,
                "prediction_score": score,
                "explanation": explanation,
                "html_body": html_body or "",
                "internal_date": internal_date,
                "extra": extra_payload
            },
            "label": label,
            "score": score,
            "intel_flags": 0,
            "impersonation_hits": 0
        }



    model_res = _safe_predict(combined_text)
    
    label = model_res.get("label")
    score = float(model_res.get("score", 0))
    explanation = model_res.get("explanation", "") or ""

    try:
        heur_adj, heur_exp, risk_links = heuristics.score_heuristics(
            body,
            {"From": sender, "URLs": urls},
            model_only=strict_mode
        )
    except Exception as e:
        logger.exception("[HEUR] score_heuristics raised: %s", e)
        heur_adj, heur_exp, risk_links = 0.0, "", []

    try:
        spf_res, dkim_res, dmarc_res = verify_message_auth(raw_data, sender)
    except Exception as e:
        logger.exception("[AUTH] verify_message_auth failed: %s", e)
        spf_res, dkim_res, dmarc_res = "unknown", "unknown", "unknown"

    try:
        ti_results = threat_intel.intel_enrich(urls) or []
    except Exception as e:
        logger.exception("[TI] intel_enrich failed: %s", e)
        ti_results = []

    try:
        sender_ti = {}
        # optionally use resolve_brand on sender domain
        sdom = None
        try:
            sdom = sender.split("@", 1)[1].lower() if "@" in sender else None
        except Exception:
            sdom = None
        if sdom:
            try:
                b = resolve_brand(sdom)
                if b:
                    sender_ti = {"brand": b, "source": "resolve_brand"}
            except Exception:
                sender_ti = {}
    except Exception:
        sender_ti = {}

    # Combine scores
    try:
        if strict_mode:
            final_score = score
        else:
            final_score = min(max(score + heur_adj * 0.3, 0.0), 1.0)

            if label == "safe":
                if heur_adj > 0.6:
                    label = "phish"
                    explanation = (explanation + " Heuristics strongly suggest phishing: " + (heur_exp or "")).strip()
                elif heur_adj > 0.2:
                    label = "maybephish"
                    explanation = (explanation + " Suspicious patterns found. " + (heur_exp or "")).strip()
            elif label == "phish" and heur_adj < -0.4:
                label = "safe"
                explanation = (explanation + " Heuristics correction: " + (heur_exp or "")).strip()
            elif heur_exp:
                explanation = (explanation + " " + heur_exp).strip()
    except Exception as e:
        logger.exception("[SCORE] combining scores failed: %s", e)
        final_score = score

    attachment_count = len(attachments)

    # Count impersonations from risk_links
    impersonation_hits = 0
    try:
        for rl in (risk_links or []):
            if isinstance(rl, dict) and rl.get("impersonates"):
                impersonation_hits += 1
    except Exception:
        impersonation_hits = 0

    extra = {
        "risk_links": risk_links,
        "intel_links": ti_results,
        "sender_intel": sender_ti,
        "spf_result": spf_res,
        "dkim_result": dkim_res,
        "dmarc_result": dmarc_res,
        "attachments": attachments,
    }


    # ============================================================
    # USER OVERRIDE HANDLING (STRICT-MATCH)
    #   - If a manual override exists and the model's final label
    #     exactly matches the manual label -> remove the override.
    #   - Otherwise, do not modify model prediction stored in DB.
    # ============================================================
    try:
        override = email_cache.get_manual_override(msg_id)
        if override:
            manual_label = (override.get("label") or "").strip().lower()
            model_label = (label or "").strip().lower()

            if manual_label in ("safe", "phish"):
                # Strict match: remove override only when model final label equals manual label
                if manual_label == model_label:
                    try:
                        email_cache.clear_manual_override(msg_id)
                        logger.debug("[SYNC][OVERRIDE] cleared override for %s (model matched manual)", msg_id)
                    except Exception as _e:
                        logger.exception("[SYNC][OVERRIDE] failed to clear override for %s: %s", msg_id, _e)
                else:
                    # Keep manual override intact; do NOT overwrite stored model prediction here.
                    # UI will apply manual override when reading the cached email.
                    pass
    except Exception as e:
        logger.exception("[SYNC][OVERRIDE] override handling failed: %s", e)


    logger.info(
        f"[ANALYST] { (msg_id or '')[:8] } | Model={score:.3f} | Heur={heur_adj:.3f} | Final={final_score:.3f} | "
        f"Label={ (label or 'N/A') } | SPF={spf_res} DKIM={dkim_res} DMARC={dmarc_res} | Attach={attachment_count} | Impersonates={impersonation_hits}"
    )

    intel_flags = 0
    try:
        for r in (ti_results or []):
            if isinstance(r, dict):
                vt = r.get("vt_verdict") or r.get("intel_vt") or "unknown"
                gsb = r.get("gsb_verdict") or r.get("intel_gsb") or "unknown"
                if vt in ("malicious", "suspicious") or gsb == "malicious":
                    intel_flags += 1
    except Exception:
        intel_flags = 0

    # Return email data for batching instead of caching directly
    logger.debug(f"[DEBUG] Full analysis email {msg_id[:8]} - will be batched")
    return {
        "email_data": {
            "msg_id": msg_id,
            "subject": subject,
            "sender": sender,
            "date": date,
            "snippet": snippet,
            "body": body,
            "raw": raw_data,
            "prediction_label": label,
            "prediction_score": final_score,
            "explanation": explanation,
            "html_body": html_body or "",
            "internal_date": internal_date,
            "extra": extra
        },
        "label": label,
        "score": final_score,
        "intel_flags": intel_flags,
        "impersonation_hits": impersonation_hits
    }


def _sync_streaming(user_email=None, max_emails=None):
    """
    Streaming sync that fetches and processes emails in small batches to handle large volumes.
    Much more robust than trying to fetch everything at once.
    """
    if sync_status.get("running"):
        logger.info("[SYNC] already running, skipping streaming sync")
        return

    if max_emails is None:
        max_emails = SYNC_MAX_FETCH_RESULTS

    sync_status["running"] = True
    run_start = time.time()
    summary = {
        "fetched": 0, "processed": 0, "failures": 0, "intel_flagged": 0, "impersonation_hits": 0, "duration_sec": 0.0
    }

    logger.info(f"[SYNC] Starting streaming sync for up to {max_emails} emails...")

    try:
        service = gmail_utils.get_service(user_email)
        if not service:
            logger.error("[SYNC] No Gmail service available for streaming sync")
            return

        # Get total message count first
        total_messages = 0
        try:
            # First try to get profile info (preferred method)
            profile = service.users().getProfile(userId="me").execute()
            total_messages = int(profile.get("messagesTotal", 0))
            logger.info(f"[SYNC] Account has {total_messages} total messages (from profile)")
        except Exception as e:
            logger.warning(f"[SYNC] Could not get profile info: {e}")
            # Fallback: use messages.list with maxResults=1 to get resultSizeEstimate
            try:
                logger.info("[SYNC] Attempting to get message count via messages.list...")
                response = service.users().messages().list(
                    userId="me",
                    includeSpamTrash=True,
                    maxResults=1  # We only need 1 to get the estimate
                ).execute()
                total_messages = int(response.get("resultSizeEstimate", 0))
                logger.info(f"[SYNC] Account has approximately {total_messages} total messages (estimated via list)")
            except Exception as e2:
                logger.warning(f"[SYNC] Could not get message count via list either: {e2}")
                # Last resort: proceed without knowing the total, but sync until we run out
                total_messages = float('inf')  # Will sync until no more messages
                logger.info("[SYNC] Proceeding without known message count - will sync all available messages")

        # Fetch messages in larger batches for better throughput
        batch_size = 500  # Maximum allowed by Gmail API for efficiency
        total_fetched = 0
        total_processed = 0
        total_failures = 0
        next_page_token = None
        email_batch = []
        batch_counter = 0

        def flush_batch():
            """Flush accumulated analyzed emails to database"""
            nonlocal email_batch, batch_counter
            if email_batch:
                batch_size_db = len(email_batch)
                batch_counter += 1
                logger.info(f"[SYNC] FLUSHING BATCH #{batch_counter}: Saving {batch_size_db} analyzed emails to database...")

                success_count = 0
                fail_count = 0

                for processed_result in email_batch:
                    if processed_result and 'email_data' in processed_result:
                        email_data = processed_result['email_data']
                        msg_id = email_data.get('msg_id', 'unknown')
                        try:
                            email_cache.cache_email(**email_data)
                            success_count += 1
                            logger.debug(f"[SYNC] Saved email {msg_id[:8]} to database")
                        except Exception as e:
                            fail_count += 1
                            logger.exception(f"[SYNC] Failed to cache email {msg_id}: {e}")

                try:
                    total_in_db = email_cache.get_total_count()
                    logger.info(f"[SYNC] Batch #{batch_counter} saved: {success_count}/{batch_size_db} emails, {fail_count} failed. Total in DB: {total_in_db}")
                except Exception as e:
                    logger.warning(f"[SYNC] Could not check DB count: {e}")

                email_batch = []

        while (total_fetched < max_emails or max_emails == -1) and total_messages != float('inf'):
            try:
                # Rate limiting
                while not gmail_utils._consume_token("gmail"):
                    time.sleep(0.2)

                # Fetch next batch of message IDs
                # For unlimited sync (max_emails == -1), just use batch_size
                # For limited sync, use min(batch_size, remaining_emails)
                if max_emails == -1:
                    current_max_results = batch_size
                else:
                    remaining = max_emails - total_fetched
                    current_max_results = min(batch_size, remaining)

                response = service.users().messages().list(
                    userId="me",
                    includeSpamTrash=True,
                    maxResults=current_max_results,
                    pageToken=next_page_token
                ).execute()

                messages_meta = response.get("messages", [])
                next_page_token = response.get("nextPageToken")

                if not messages_meta:
                    logger.info("[SYNC] No more messages to fetch")
                    break

                current_batch_size = len(messages_meta)
                logger.info(f"[SYNC] Fetched {current_batch_size} message IDs (total fetched: {total_fetched + current_batch_size})")

                # Process this batch immediately
                batch_messages = []
                for meta in messages_meta:
                    try:
                        # Rate limiting per message
                        while not gmail_utils._consume_token("gmail"):
                            time.sleep(0.2)

                        full_msg = service.users().messages().get(
                            userId="me", id=meta["id"], format="raw"
                        ).execute()

                        # Extract message data
                        msg_id = full_msg.get("id")
                        internal_date = int(full_msg.get("internalDate", 0))
                        raw_data = full_msg.get("raw", "")
                        raw_bytes = base64.urlsafe_b64decode(raw_data.encode("utf-8"))

                        from email import policy
                        from email.parser import BytesParser
                        mime = BytesParser(policy=policy.default).parsebytes(raw_bytes)
                        subject = mime.get("subject", "")
                        sender = mime.get("from", "")
                        date = mime.get("date", "")
                        snippet = full_msg.get("snippet", "")

                        text_body, html_body = gmail_utils.extract_bodies_from_mime(raw_bytes)

                        # Get attachments
                        try:
                            meta_msg = service.users().messages().get(
                                userId="me", id=msg_id, format="full"
                            ).execute()
                            attachments = gmail_utils.extract_attachments(service, "me", meta_msg)
                        except Exception:
                            attachments = []

                        # Extract URLs
                        if html_body:
                            cleaned_text, urls = gmail_utils.clean_html_for_text(html_body)
                        elif text_body:
                            cleaned_text, urls = gmail_utils.clean_html_for_text(text_body)
                        else:
                            cleaned_text, urls = "", []

                        if not cleaned_text.strip():
                            if attachments:
                                cleaned_text = "NO TEXT DETECTED; possibly an empty email with attachment(s)"
                            else:
                                cleaned_text = "NO TEXT DETECTED; possibly an empty email"

                        batch_messages.append({
                            "id": msg_id,
                            "msg_id": msg_id,
                            "subject": subject,
                            "sender": sender,
                            "date": date,
                            "internal_date": internal_date,
                            "snippet": snippet,
                            "body": f"{subject}. {cleaned_text}".strip(),
                            "html_body": html_body,
                            "raw": raw_data,
                            "urls": urls,
                            "attachments": attachments,
                        })

                        # IMMEDIATE DISPLAY: Cache email right after download for instant user visibility
                        try:
                            email_cache.cache_email_immediately(
                                msg_id=msg_id,
                                subject=subject,
                                sender=sender,
                                date=date,
                                snippet=snippet,
                                body=f"{subject}. {cleaned_text}".strip(),
                                html_body=html_body,
                                raw=raw_data,
                                internal_date=internal_date
                            )
                            logger.debug(f"[SYNC] Cached email immediately: {msg_id[:8]} (status: analyzing)")
                        except Exception as e:
                            logger.warning(f"[SYNC] Failed to cache email immediately {msg_id[:8]}: {e}")

                    except Exception as e:
                        logger.warning(f"[SYNC] Failed to fetch message {meta['id']}: {e}")
                        total_failures += 1
                        continue

                # Process messages through phishing analysis
                if batch_messages:
                    logger.info(f"[SYNC] Processing {len(batch_messages)} messages through analysis...")

                    with ThreadPoolExecutor(max_workers=min(SYNC_PARALLELISM, len(batch_messages))) as executor:
                        futures = {executor.submit(process_single_email, msg): msg for msg in batch_messages}
                        for future in as_completed(futures):
                            try:
                                processed_result = future.result()
                                if processed_result:
                                    email_batch.append(processed_result)
                                    total_processed += 1

                                    # Flush when batch reaches threshold
                                    if len(email_batch) >= (WAIT_TILL_FEED_DATABASE * 10):
                                        flush_batch()

                            except Exception as e:
                                logger.exception(f"[SYNC] Analysis failed: {e}")
                                total_failures += 1

                total_fetched += current_batch_size

                # Log progress
                logger.info(f"[SYNC] Progress: {total_processed}/{total_fetched} processed, {total_failures} failures")

                # Check if we've hit the limit
                if total_fetched >= max_emails:
                    logger.info(f"[SYNC] Reached maximum email limit: {max_emails}")
                    break

                # If no more pages, we're done
                if not next_page_token:
                    logger.info("[SYNC] Reached end of all messages")
                    break

            except Exception as e:
                logger.exception(f"[SYNC] Error in streaming batch: {e}")
                break

        # Flush any remaining emails
        if email_batch:
            logger.info(f"[SYNC] Flushing final batch of {len(email_batch)} emails...")
            flush_batch()

        summary.update({
            "fetched": total_fetched,
            "processed": total_processed,
            "failures": total_failures
        })

        logger.info(f"[SYNC] Streaming sync complete: {total_processed}/{total_fetched} emails processed successfully")

    except Exception as e:
        logger.exception("[SYNC] Fatal error in streaming sync: {e}")
    finally:
        run_end = time.time()
        duration = run_end - run_start
        summary["duration_sec"] = duration
        sync_status.update({
            "running": False,
            "last_sync": time.strftime("%Y-%m-%d %H:%M:%S"),
            "stats": summary
        })

        # Record performance for auto-optimization
        if AUTO_OPTIMIZE_ENABLED:
            sync_optimizer.record_sync_performance(summary)

        logger.info("[SYNC] Streaming sync finished (duration=%.2fs)", duration)


def _sync_once(user_email=None):
    """Fallback to streaming sync for better reliability"""
    if CONCURRENT_FETCHING_ENABLED:
        return _sync_concurrent(user_email, SYNC_MAX_FETCH_RESULTS)
    else:
        return _sync_streaming(user_email, SYNC_MAX_FETCH_RESULTS)


def _sync_concurrent(user_email=None, max_emails=None):
    """
    Concurrent sync that runs fetching and analysis in parallel threads.
    Fetcher continuously fetches emails and puts them in a queue.
    Analyzer continuously takes emails from the queue and processes them.
    """
    if sync_status.get("running"):
        logger.info("[SYNC] already running, skipping concurrent sync")
        return

    if max_emails is None:
        max_emails = SYNC_MAX_FETCH_RESULTS

    sync_status["running"] = True
    sync_status["mode"] = "concurrent"
    run_start = time.time()

    # Thread-safe queue for emails between fetcher and analyzer
    email_queue = queue.Queue(maxsize=FETCH_QUEUE_SIZE)

    # Shared counters using thread-safe operations
    counters = {
        "fetched": 0,
        "processed": 0,
        "failures": 0,
        "completed": False
    }
    counters_lock = threading.Lock()

    # Shutdown event for clean thread termination
    shutdown_event = threading.Event()

    summary = {
        "fetched": 0, "processed": 0, "failures": 0, "intel_flagged": 0, "impersonation_hits": 0, "duration_sec": 0.0
    }

    logger.info(f"[SYNC] Starting concurrent sync for up to {max_emails} emails...")

    def email_fetcher():
        """Fetcher thread: continuously fetches emails and puts them in queue"""
        try:
            service = gmail_utils.get_service(user_email)
            if not service:
                logger.error("[SYNC] No Gmail service available for concurrent sync")
                return

            # Get total message count
            total_messages = 0
            try:
                profile = service.users().getProfile(userId="me").execute()
                total_messages = int(profile.get("messagesTotal", 0))
                logger.info(f"[SYNC] Account has {total_messages} total messages")
            except Exception as e:
                logger.warning(f"[SYNC] Could not get message count: {e}")
                total_messages = float('inf')

            next_page_token = None
            local_fetched = 0

            while not shutdown_event.is_set() and (local_fetched < max_emails or max_emails == -1):
                try:
                    # Rate limiting
                    while not gmail_utils._consume_token("gmail") and not shutdown_event.is_set():
                        time.sleep(0.2)

                    if shutdown_event.is_set():
                        break

                    # Fetch next batch of message IDs
                    if max_emails == -1:
                        current_max_results = FETCH_BATCH_SIZE
                    else:
                        remaining = max_emails - local_fetched
                        current_max_results = min(FETCH_BATCH_SIZE, remaining)

                    response = service.users().messages().list(
                        userId="me",
                        includeSpamTrash=True,
                        maxResults=current_max_results,
                        pageToken=next_page_token
                    ).execute()

                    messages_meta = response.get("messages", [])
                    next_page_token = response.get("nextPageToken")

                    if not messages_meta:
                        logger.info("[SYNC] Fetcher: No more messages to fetch")
                        break

                    logger.info(f"[SYNC] Fetcher: Got {len(messages_meta)} message IDs")

                    # Fetch full message data for this batch
                    for meta in messages_meta:
                        if shutdown_event.is_set():
                            break

                        try:
                            # Rate limiting per message
                            while not gmail_utils._consume_token("gmail") and not shutdown_event.is_set():
                                time.sleep(0.2)

                            if shutdown_event.is_set():
                                break

                            full_msg = service.users().messages().get(
                                userId="me", id=meta["id"], format="raw"
                            ).execute()

                            # Extract message data
                            msg_id = full_msg.get("id")
                            internal_date = int(full_msg.get("internalDate", 0))
                            raw_data = full_msg.get("raw", "")
                            raw_bytes = base64.urlsafe_b64decode(raw_data.encode("utf-8"))

                            from email import policy
                            from email.parser import BytesParser
                            mime = BytesParser(policy=policy.default).parsebytes(raw_bytes)
                            subject = mime.get("subject", "")
                            sender = mime.get("from", "")
                            date = mime.get("date", "")
                            snippet = full_msg.get("snippet", "")

                            text_body, html_body = gmail_utils.extract_bodies_from_mime(raw_bytes)

                            # Get attachments
                            try:
                                meta_msg = service.users().messages().get(
                                    userId="me", id=msg_id, format="full"
                                ).execute()
                                attachments = gmail_utils.extract_attachments(service, "me", meta_msg)
                            except Exception:
                                attachments = []

                            # Extract URLs
                            if html_body:
                                cleaned_text, urls = gmail_utils.clean_html_for_text(html_body)
                            elif text_body:
                                cleaned_text, urls = gmail_utils.clean_html_for_text(text_body)
                            else:
                                cleaned_text, urls = "", []

                            if not cleaned_text.strip():
                                if attachments:
                                    cleaned_text = "NO TEXT DETECTED; possibly an empty email with attachment(s)"
                                else:
                                    cleaned_text = "NO TEXT DETECTED; possibly an empty email"

                            email_data = {
                                "id": msg_id,
                                "msg_id": msg_id,
                                "subject": subject,
                                "sender": sender,
                                "date": date,
                                "internal_date": internal_date,
                                "snippet": snippet,
                                "body": f"{subject}. {cleaned_text}".strip(),
                                "html_body": html_body,
                                "raw": raw_data,
                                "urls": urls,
                                "attachments": attachments,
                            }

                            # IMMEDIATE DISPLAY: Cache email right after download
                            try:
                                email_cache.cache_email_immediately(
                                    msg_id=msg_id,
                                    subject=subject,
                                    sender=sender,
                                    date=date,
                                    snippet=snippet,
                                    body=f"{subject}. {cleaned_text}".strip(),
                                    html_body=html_body,
                                    raw=raw_data,
                                    internal_date=internal_date
                                )
                                logger.debug(f"[SYNC] Cached email immediately: {msg_id[:8]} (status: analyzing)")
                            except Exception as e:
                                logger.warning(f"[SYNC] Failed to cache email immediately {msg_id[:8]}: {e}")

                            # Put email in queue for analysis (with timeout to avoid blocking)
                            try:
                                email_queue.put(email_data, timeout=1.0)
                                with counters_lock:
                                    counters["fetched"] += 1
                                local_fetched += 1
                                logger.debug(f"[SYNC] Queued email {msg_id[:8]} for analysis (queue size: {email_queue.qsize()})")
                            except queue.Full:
                                logger.warning("[SYNC] Email queue is full, waiting...")
                                time.sleep(0.5)
                                continue

                        except Exception as e:
                            logger.warning(f"[SYNC] Failed to fetch message {meta['id']}: {e}")
                            with counters_lock:
                                counters["failures"] += 1
                            continue

                    # Check if we've hit the limit
                    if local_fetched >= max_emails and max_emails != -1:
                        logger.info(f"[SYNC] Fetcher: Reached maximum email limit: {max_emails}")
                        break

                    # If no more pages, we're done
                    if not next_page_token:
                        logger.info("[SYNC] Fetcher: Reached end of all messages")
                        break

                except Exception as e:
                    logger.exception(f"[SYNC] Error in fetcher batch: {e}")
                    time.sleep(1)  # Brief pause before retry
                    continue

            logger.info(f"[SYNC] Fetcher completed: {local_fetched} emails fetched")

        except Exception as e:
            logger.exception("[SYNC] Fatal error in fetcher: {e}")
        finally:
            # Signal that fetching is complete
            with counters_lock:
                counters["completed"] = True

    def email_analyzer():
        """Analyzer thread: continuously processes emails from queue"""
        email_batch = []
        batch_counter = 0

        def flush_batch():
            """Flush accumulated analyzed emails to database"""
            nonlocal email_batch, batch_counter
            if email_batch:
                batch_size_db = len(email_batch)
                batch_counter += 1
                logger.info(f"[SYNC] FLUSHING ANALYSIS BATCH #{batch_counter}: Saving {batch_size_db} analyzed emails...")

                success_count = 0
                fail_count = 0

                for processed_result in email_batch:
                    if processed_result and 'email_data' in processed_result:
                        email_data = processed_result['email_data']
                        msg_id = email_data.get('msg_id', 'unknown')
                        try:
                            email_cache.cache_email(**email_data)
                            success_count += 1
                            logger.debug(f"[SYNC] Saved analyzed email {msg_id[:8]} to database")
                        except Exception as e:
                            fail_count += 1
                            logger.exception(f"[SYNC] Failed to cache analyzed email {msg_id}: {e}")

                try:
                    total_in_db = email_cache.get_total_count()
                    logger.info(f"[SYNC] Analysis batch #{batch_counter} saved: {success_count}/{batch_size_db} emails, {fail_count} failed. Total in DB: {total_in_db}")
                except Exception as e:
                    logger.warning(f"[SYNC] Could not check DB count: {e}")

                email_batch = []

        try:
            while not shutdown_event.is_set():
                try:
                    # Get email from queue (with timeout to allow shutdown checks)
                    email_data = email_queue.get(timeout=0.5)

                    # Process the email
                    try:
                        processed_result = process_single_email(email_data)
                        if processed_result:
                            email_batch.append(processed_result)
                            with counters_lock:
                                counters["processed"] += 1

                            # Flush when batch reaches threshold
                            if len(email_batch) >= (WAIT_TILL_FEED_DATABASE * 10):
                                flush_batch()

                        logger.debug(f"[SYNC] Processed email {email_data.get('msg_id', 'unknown')[:8]}")

                    except Exception as e:
                        logger.exception(f"[SYNC] Analysis failed for email {email_data.get('msg_id', 'unknown')}: {e}")
                        with counters_lock:
                            counters["failures"] += 1

                    # Mark task as done
                    email_queue.task_done()

                except queue.Empty:
                    # Check if fetcher is done and queue is empty
                    with counters_lock:
                        if counters["completed"] and email_queue.empty():
                            logger.info("[SYNC] Analyzer: No more emails to process")
                            break
                    continue

            # Flush any remaining emails
            if email_batch:
                logger.info(f"[SYNC] Analyzer: Flushing final batch of {len(email_batch)} emails...")
                flush_batch()

            logger.info(f"[SYNC] Analyzer completed: {batch_counter} batches processed")

        except Exception as e:
            logger.exception("[SYNC] Fatal error in analyzer: {e}")

    try:
        # Start fetcher and analyzer threads
        fetcher_thread = threading.Thread(target=email_fetcher, daemon=True, name="EmailFetcher")
        analyzer_thread = threading.Thread(target=email_analyzer, daemon=True, name="EmailAnalyzer")

        fetcher_thread.start()
        analyzer_thread.start()

        logger.info("[SYNC] Started concurrent fetcher and analyzer threads")

        # Monitor progress and wait for completion
        last_log_time = time.time()
        while True:
            time.sleep(1)  # Check every second

            with counters_lock:
                current_fetched = counters["fetched"]
                current_processed = counters["processed"]
                current_failures = counters["failures"]
                fetcher_done = counters["completed"]

            # Log progress periodically
            if time.time() - last_log_time >= 10:  # Every 10 seconds
                logger.info(f"[SYNC] Progress: {current_processed}/{current_fetched} processed, {current_failures} failures, queue size: {email_queue.qsize()}")
                last_log_time = time.time()

            # Check if both threads are done
            if (not fetcher_thread.is_alive() and not analyzer_thread.is_alive()) or \
               (fetcher_done and email_queue.empty() and not analyzer_thread.is_alive()):
                break

        # Wait for threads to fully complete
        fetcher_thread.join(timeout=5)
        analyzer_thread.join(timeout=5)

        # Get final counts
        with counters_lock:
            summary.update({
                "fetched": counters["fetched"],
                "processed": counters["processed"],
                "failures": counters["failures"]
            })

        logger.info(f"[SYNC] Concurrent sync complete: {summary['processed']}/{summary['fetched']} emails processed successfully")

    except Exception as e:
        logger.exception("[SYNC] Fatal error in concurrent sync: {e}")
    finally:
        # Ensure shutdown event is set
        shutdown_event.set()

        run_end = time.time()
        duration = run_end - run_start
        summary["duration_sec"] = duration
        sync_status.update({
            "running": False,
            "last_sync": time.strftime("%Y-%m-%d %H:%M:%S"),
            "stats": summary
        })

        # Record performance for auto-optimization
        if AUTO_OPTIMIZE_ENABLED:
            sync_optimizer.record_sync_performance(summary)

        logger.info("[SYNC] Concurrent sync finished (duration=%.2fs)", duration)


def _load_sync_state(user_email):
    """Load sync state for a user to track incremental progress."""
    try:
        os.makedirs(os.path.dirname(SYNC_STATE_FILE), exist_ok=True)
        if os.path.exists(SYNC_STATE_FILE):
            import json
            with open(SYNC_STATE_FILE, 'r') as f:
                all_states = json.load(f)
                return all_states.get(user_email, {})
    except Exception as e:
        logger.warning(f"[SYNC] Failed to load sync state: {e}")
    return {}


def _save_sync_state(user_email, state):
    """Save sync state for a user."""
    try:
        os.makedirs(os.path.dirname(SYNC_STATE_FILE), exist_ok=True)
        import json
        # Load existing states
        all_states = {}
        if os.path.exists(SYNC_STATE_FILE):
            try:
                with open(SYNC_STATE_FILE, 'r') as f:
                    all_states = json.load(f)
            except:
                all_states = {}

        # Update state for this user
        all_states[user_email] = state

        # Save back
        with open(SYNC_STATE_FILE, 'w') as f:
            json.dump(all_states, f, indent=2)
    except Exception as e:
        logger.warning(f"[SYNC] Failed to save sync state: {e}")


def _sync_incremental(user_email=None):
    """
    Perform incremental sync in batches to handle large Gmail accounts.
    Tracks progress across multiple runs and resumes where it left off.
    """
    if not user_email:
        logger.warning("[SYNC] Incremental sync requires user_email")
        return _sync_once(user_email)  # Fall back to regular sync

    if sync_status.get("running"):
        logger.info("[SYNC] already running, skipping incremental sync")
        return

    sync_status["running"] = True
    run_start = time.time()

    try:
        # Load sync state for this user
        state = _load_sync_state(user_email)
        next_page_token = state.get("next_page_token")
        total_processed = state.get("total_processed", 0)
        last_run = state.get("last_run")

        logger.info(f"[SYNC] Starting incremental sync for {user_email} (processed so far: {total_processed})")

        # Check if we need to reset (e.g., if it's been too long since last run)
        reset_sync = False
        if last_run:
            try:
                import datetime
                last_run_dt = datetime.datetime.fromisoformat(last_run.replace('Z', '+00:00'))
                days_since_last_run = (datetime.datetime.now(datetime.timezone.utc) - last_run_dt).days
                if days_since_last_run > 7:  # Reset after 7 days of inactivity
                    logger.info("[SYNC] Resetting incremental sync state (too old)")
                    reset_sync = True
            except:
                reset_sync = True

        if reset_sync:
            next_page_token = None
            total_processed = 0

        # Fetch messages in batches
        batches_processed = 0
        total_fetched_this_run = 0
        total_processed_this_run = 0
        total_failures_this_run = 0

        while batches_processed < SYNC_MAX_INCREMENTAL_BATCHES:
            try:
                # Use Gmail's pagination to get the next batch
                service = gmail_utils.get_service(user_email)
                if not service:
                    logger.error("[SYNC] No Gmail service available for incremental sync")
                    break

                # Rate limiting
                while not gmail_utils._consume_token("gmail"):
                    time.sleep(0.2)

                # Fetch next batch
                response = service.users().messages().list(
                    userId="me",
                    includeSpamTrash=True,
                    maxResults=SYNC_BATCH_SIZE,
                    pageToken=next_page_token
                ).execute()

                messages_meta = response.get("messages", [])
                next_page_token = response.get("nextPageToken")

                if not messages_meta:
                    logger.info("[SYNC] No more messages to fetch - incremental sync complete!")
                    # Clear the next_page_token to indicate completion
                    state["next_page_token"] = None
                    state["completed"] = True
                    _save_sync_state(user_email, state)
                    break

                # Get full message details for this batch
                batch_messages = []
                for meta in messages_meta:
                    try:
                        # Rate limiting per message
                        while not gmail_utils._consume_token("gmail"):
                            time.sleep(0.2)

                        full_msg = service.users().messages().get(
                            userId="me", id=meta["id"], format="raw"
                        ).execute()

                        # Process message data (similar to gmail_utils.fetch_all_messages)
                        msg_id = full_msg.get("id")
                        internal_date = int(full_msg.get("internalDate", 0))
                        raw_data = full_msg.get("raw", "")
                        raw_bytes = base64.urlsafe_b64decode(raw_data.encode("utf-8"))

                        from email import policy
                        from email.parser import BytesParser
                        mime = BytesParser(policy=policy.default).parsebytes(raw_bytes)
                        subject = mime.get("subject", "")
                        sender = mime.get("from", "")
                        date = mime.get("date", "")
                        snippet = full_msg.get("snippet", "")

                        text_body, html_body = gmail_utils.extract_bodies_from_mime(raw_bytes)

                        # Attachments
                        meta_msg = service.users().messages().get(
                            userId="me", id=msg_id, format="full"
                        ).execute()
                        attachments = gmail_utils.extract_attachments(service, "me", meta_msg)

                        if html_body:
                            cleaned_text, urls = gmail_utils.clean_html_for_text(html_body)
                        elif text_body:
                            cleaned_text, urls = gmail_utils.clean_html_for_text(text_body)
                        else:
                            cleaned_text, urls = "", []

                        if not cleaned_text.strip():
                            if attachments:
                                cleaned_text = "NO TEXT DETECTED; possibly an empty email with attachment(s)"
                            else:
                                cleaned_text = "NO TEXT DETECTED; possibly an empty email"

                        batch_messages.append({
                            "id": msg_id,
                            "msg_id": msg_id,
                            "subject": subject,
                            "sender": sender,
                            "date": date,
                            "internal_date": internal_date,
                            "snippet": snippet,
                            "body": f"{subject}. {cleaned_text}".strip(),
                            "html_body": html_body,
                            "raw": raw_data,
                            "urls": urls,
                            "attachments": attachments,
                        })

                    except Exception as e:
                        logger.warning(f"[SYNC] Failed to fetch message {meta['id']}: {e}")
                        continue

                if not batch_messages:
                    logger.warning("[SYNC] No messages could be processed in this batch")
                    break

                # Process the batch with batching (same logic as _sync_once)
                logger.info(f"[SYNC] Processing batch {batches_processed + 1} with {len(batch_messages)} messages")

                processed_count = 0
                failures = 0
                email_batch = []  # Local batch for this incremental batch
                local_batch_counter = 0

                def flush_incremental_batch():
                    """Flush accumulated analyzed emails to database for incremental sync"""
                    nonlocal email_batch, local_batch_counter
                    if email_batch:
                        batch_size = len(email_batch)
                        local_batch_counter += 1
                        logger.info(f"[SYNC] FLUSHING INCREMENTAL BATCH #{local_batch_counter}: Saving {batch_size} analyzed emails to database...")

                        success_count = 0
                        fail_count = 0

                        for processed_result in email_batch:
                            if processed_result and 'email_data' in processed_result:
                                email_data = processed_result['email_data']
                                msg_id = email_data.get('msg_id', 'unknown')
                                try:
                                    # Use the analyzed email data directly
                                    email_cache.cache_email(**email_data)
                                    success_count += 1
                                    logger.debug(f"[SYNC] Saved incremental email {msg_id[:8]} to database")
                                except Exception as e:
                                    fail_count += 1
                                    logger.exception(f"[SYNC] Failed to cache incremental email {msg_id}: {e}")

                        # Check total emails in database after flush
                        try:
                            total_emails = email_cache.get_total_count()
                            logger.info(f"[SYNC] Incremental batch #{local_batch_counter} flush complete: {success_count}/{batch_size} emails saved, {fail_count} failed")
                            logger.info(f"[SYNC] Total emails in database: {total_emails}")
                        except Exception as e:
                            logger.warning(f"[SYNC] Could not check total email count: {e}")

                        email_batch = []

                # Calculate actual batch size for incremental sync (same as regular sync)
                actual_batch_size = WAIT_TILL_FEED_DATABASE * 10

                with ThreadPoolExecutor(max_workers=SYNC_PARALLELISM) as ex:
                    futures = {ex.submit(process_single_email, m): m for m in batch_messages}
                    for fut in as_completed(futures):
                        try:
                            res = fut.result()
                            if res:
                                processed_count += 1
                                email_batch.append(res)

                                # Flush batch when it reaches the threshold
                                if len(email_batch) >= actual_batch_size:
                                    logger.info(f"[SYNC] Incremental batch full (size={len(email_batch)}), triggering database flush...")
                                    flush_incremental_batch()

                        except Exception as e:
                            failures += 1
                            logger.exception("[SYNC] processing a message failed: %s", e)

                # Flush any remaining emails in the incremental batch
                if email_batch:
                    logger.info(f"[SYNC] Flushing final incremental batch (size={len(email_batch)})...")
                    flush_incremental_batch()

                # Update counters
                total_fetched_this_run += len(batch_messages)
                total_processed_this_run += processed_count
                total_failures_this_run += failures
                total_processed += processed_count
                batches_processed += 1

                logger.info(f"[SYNC] Incremental batch {batches_processed} complete: {processed_count}/{len(batch_messages)} processed, {failures} failures, {local_batch_counter} database flushes")

                # Save progress
                state.update({
                    "next_page_token": next_page_token,
                    "total_processed": total_processed,
                    "last_run": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "completed": False
                })
                _save_sync_state(user_email, state)

                # If no more pages, we're done
                if not next_page_token:
                    logger.info("[SYNC] Reached end of messages - incremental sync complete!")
                    state["completed"] = True
                    _save_sync_state(user_email, state)
                    break

            except Exception as e:
                logger.exception(f"[SYNC] Error in incremental batch {batches_processed}: {e}")
                break

        # Final summary
        run_end = time.time()
        duration = run_end - run_start

        summary = {
            "mode": "incremental",
            "batches_processed": batches_processed,
            "fetched": total_fetched_this_run,
            "processed": total_processed_this_run,
            "failures": total_failures_this_run,
            "total_processed_ever": total_processed,
            "duration_sec": duration,
            "completed": state.get("completed", False)
        }

        sync_status.update({
            "running": False,
            "last_sync": time.strftime("%Y-%m-%d %H:%M:%S"),
            "stats": summary
        })

        logger.info("[SYNC] Incremental run finished (duration=%.2fs) summary=%s", duration, summary)

    except Exception as e:
        logger.exception("[SYNC] Fatal error in incremental sync: %s", e)
    finally:
        sync_status["running"] = False


def _local_recheck_loop(interval):
    """
    Periodically re-evaluate ALL cached messages using process_single_email(),
    without contacting Gmail. Controlled entirely by LOCAL_RECHECK_INTERVAL.
    """
    logger.info(f"[RECHECK] Local re-evaluation loop started (interval={interval}s)")
    while True:
        try:
            ids = get_all_msg_ids()
            logger.info(f"[RECHECK] Starting batch re-evaluation of {len(ids)} messages")

            for msg_id in ids:
                try:
                    item = get_cached_email(msg_id)
                    if item:
                        process_single_email(item)
                except Exception as e:
                    logger.exception(f"[RECHECK] Failed for {msg_id}: {e}")

            logger.info("[RECHECK] Completed batch re-evaluation")

        except Exception as e:
            logger.exception(f"[RECHECK] Fatal loop error: {e}")

        time.sleep(interval)



def start_continuous_sync(interval):
    def loop():
        backoff_attempt = 0
        while True:
            try:
                # Try to determine user email for incremental sync
                user_email = None
                try:
                    # Check if we have any user tokens to determine which sync mode to use
                    import os
                    user_tokens_dir = os.path.join(os.path.dirname(__file__), "cache", "user_tokens")
                    if os.path.exists(user_tokens_dir):
                        for filename in os.listdir(user_tokens_dir):
                            if filename.endswith('.json'):
                                user_email = filename.replace('.json', '')
                                break
                except Exception:
                    user_email = None

                # Use concurrent sync by default, fallback to incremental for large accounts
                if CONCURRENT_FETCHING_ENABLED:
                    logger.info(f"[SYNC] Using concurrent sync (fetcher + analyzer threads)")
                    _sync_concurrent(user_email, SYNC_MAX_FETCH_RESULTS)
                elif user_email:
                    # Check if we should use incremental sync (based on account size or previous failures)
                    state = _load_sync_state(user_email)
                    logger.info(f"[SYNC] Using incremental sync for user {user_email}")
                    _sync_incremental(user_email)
                else:
                    # No user tokens found, use regular concurrent sync
                    logger.info("[SYNC] Using concurrent sync (no user tokens found)")
                    _sync_concurrent()

                backoff_attempt = 0
                time.sleep(interval)
            except Exception as e:
                logger.exception("[SYNC] unexpected error in continuous loop: %s", e)
                wait = min(SYNC_BACKOFF_BASE * (2 ** backoff_attempt), SYNC_BACKOFF_MAX)
                logger.warning("[SYNC] backing off for %.1fs before retry (attempt %d)", wait, backoff_attempt)
                time.sleep(wait)
                backoff_attempt += 1

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    # start local-only re-evaluation loop if enabled
    try:
        re_int = int(os.getenv("LOCAL_RECHECK_INTERVAL", "0"))
        if re_int > 0:
            t2 = threading.Thread(target=_local_recheck_loop, args=(re_int,), daemon=True)
            t2.start()
            logger.info(f"[RECHECK] Local re-evaluation enabled (interval={re_int}s)")
        else:
            logger.info("[RECHECK] Local re-evaluation disabled (LOCAL_RECHECK_INTERVAL=0)")
    except Exception:
        logger.exception("[RECHECK] Failed to start local re-evaluation loop")

    logger.info(f"[SYNC] Continuous sync thread started (concurrent={CONCURRENT_FETCHING_ENABLED}).")


def force_sync_once(user_email=None):
    _sync_once(user_email)


def get_sync_status():
    return sync_status
