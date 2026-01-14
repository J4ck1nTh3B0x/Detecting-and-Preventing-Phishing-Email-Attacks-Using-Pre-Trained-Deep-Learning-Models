# Standard library imports
import os
import sys
import json
import re
import time
import base64
import logging
import hashlib
import mimetypes
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, cast
import math 

# Third-party imports
from flask import (
    Flask, render_template, request, jsonify, abort,
    url_for, make_response, session, g, redirect
)
import requests
from markupsafe import Markup, escape

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import required modules
import email_cache
import threat_intel
import traceback
import background_sync
import gmail_utils
from phishing_detector import PhishingDetector
from intelligence.heuristics.email_analysis import analyze_email_links_and_content
from file_analyzer import analyze_attachments
import config
import user_auth

# Initialize modules
phishing_detector = PhishingDetector()

# Create alias for intelligence module
class IntelligenceModule:
    def analyze_email_links_and_content(self, *args, **kwargs):
        return analyze_email_links_and_content(*args, **kwargs)

intelligence_heuristics_email_analysis = IntelligenceModule()

# Set init_email_cache to the function from email_cache module
init_email_cache = email_cache.init_db

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', os.urandom(24).hex())

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app")

# Initialize database and services
try:
    # Ensure cache directories exist
    os.makedirs(config.EMAIL_CACHE_DIR, exist_ok=True)
    os.makedirs(config.THREAT_INTEL_CACHE, exist_ok=True)
    
    # Initialize database
    init_email_cache()
    
    logger.info("Application services initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize application services: {e}")
    # Services already initialized in the try block above

# --- User prefs for persistent per-user theme -------------------------------
_USER_PREFS_PATH = os.path.join(config.BASE_DIR, "user_prefs.json")
_USER_PREFS_LOCK = threading.Lock()

def _ensure_prefs_file() -> None:
    """Ensure the user preferences file exists."""
    p = Path(_USER_PREFS_PATH)
    if not p.exists():
        with _USER_PREFS_LOCK:
            if not p.exists():
                try:
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text("{}", encoding="utf-8")
                except Exception as e:
                    logger.error(f"Failed to create user prefs file: {e}")

def load_user_prefs() -> Dict[str, Any]:
    """Load user preferences from disk."""
    _ensure_prefs_file()
    try:
        with open(_USER_PREFS_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading user prefs: {e}")
        return {}

def save_user_prefs(prefs: Dict[str, Any]) -> None:
    """Save user preferences to disk."""
    _ensure_prefs_file()
    try:
        with _USER_PREFS_LOCK:
            with open(_USER_PREFS_PATH, 'w', encoding='utf-8') as f:
                json.dump(prefs, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error saving user prefs: {e}")

def get_user_theme(user_email: str) -> str:
    """Get the theme preference for a user."""
    if not user_email:
        return "light"
    prefs = load_user_prefs()
    return (prefs.get(str(user_email), {}) or {}).get("theme", "light")


def set_user_theme(user_email: str, theme: str) -> None:
    """Set the theme preference for a user."""
    if not user_email:
        return
    prefs = load_user_prefs()
    key = str(user_email)
    if key not in prefs or not isinstance(prefs.get(key), dict):
        prefs[key] = {}
    prefs[key]["theme"] = theme
    save_user_prefs(prefs)



def highlight_term(text, term):
    if not text or not term:
        return escape(text or "")
    pattern = re.compile(re.escape(term), re.IGNORECASE)
    highlighted = pattern.sub(lambda m: f"<mark>{escape(m.group(0))}</mark>", text)
    return Markup(highlighted)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app")

app = Flask(__name__, template_folder="templates")
# ADDED: session secret so /set_theme works and persists across pages
app.secret_key = os.environ.get("APP_SECRET_KEY", "dev-" + os.urandom(24).hex())

# --- User login (Google profile OAuth, not Gmail API OAuth) -----------------
# This enables template links like url_for('login') / url_for('logout').
try:
    user_auth.init_oauth_config(
        client_secrets_file=os.getenv("USER_AUTH_CREDENTIALS_FILE") or os.path.join(config.BASE_DIR, "credentials.json"),
        redirect_uri=os.getenv("USER_AUTH_REDIRECT_URI") or "http://localhost:8080/auth/callback",
    )
except Exception as e:
    logger.warning(f"User auth OAuth init failed: {e}")

@app.route("/login")
def login():
    """Show login page.

    IMPORTANT: We don't immediately redirect to Google.
    This lets the app:
      - show a friendly page,
      - (later) potentially detect existing login/token info,
      - avoid surprising automatic redirects.
    """
    try:
        # If user is already logged in, go to target (or home)
        if user_auth.is_logged_in():
            return redirect(request.args.get("next") or url_for("index"))

        next_url = request.args.get("next")
        if next_url:
            session["post_login_redirect"] = next_url

        # If OAuth isn't configured, show error UI
        if not getattr(user_auth, "_oauth_config", None):
            return render_template(
                "login.html",
                error="Authentication is not configured. Ensure credentials.json exists and USER_AUTH_REDIRECT_URI is authorized.",
                redirect_uri=os.getenv("USER_AUTH_REDIRECT_URI") or "http://localhost:8080/auth/callback",
                auth_url=None,
            )

        # Provide an explicit link/button the user clicks to start OAuth
        auth_url = url_for("login_start")
        return render_template(
            "login.html",
            error=None,
            redirect_uri=os.getenv("USER_AUTH_REDIRECT_URI") or "http://localhost:8080/auth/callback",
            auth_url=auth_url,
        )
    except Exception:
        logger.exception("Failed to render login page")
        return "Login failed", 500


@app.route("/login/start")
def login_start():
    """Start Google Sign-In (explicit user action)."""
    try:
        authorization_url, state = user_auth.get_authorization_url()
        session["oauth_state"] = state
        return redirect(authorization_url)
    except Exception:
        logger.exception("Failed to start login flow")
        return (
            "Login is not configured. Ensure credentials.json is present and USER_AUTH_REDIRECT_URI is authorized.",
            500,
        )


@app.route("/auth/callback")
def auth_callback():
    """OAuth callback to finalize login and store user info in session."""
    code = request.args.get("code")
    state = request.args.get("state")
    expected_state = session.get("oauth_state")

    # More lenient state validation for development (allows access from different IPs/hosts)
    # In production, you might want to make this stricter
    if expected_state and state and state != expected_state:
        logger.warning(f"OAuth state mismatch: expected {expected_state}, got {state}. Allowing for development flexibility.")
        # Don't fail - continue with login for development convenience

    if not code:
        return "Missing authorization code", 400

    user_info, _creds = user_auth.get_user_info_from_code(code, state)
    if not user_info:
        return "Login failed", 500

    session["user_email"] = user_info.get("email")
    session["user_name"] = user_info.get("name")
    session["user_picture"] = user_info.get("picture")

    # Optionally restore per-user theme preference after login
    try:
        user_email = session.get("user_email")
        if user_email:
            theme = get_user_theme(str(user_email))
            if theme:
                session["theme"] = theme
    except Exception:
        pass

    redirect_to = session.pop("post_login_redirect", None) or url_for("index")
    return redirect(redirect_to)


@app.route("/logout")
def logout():
    """Logout user (clears session and browser cookies)."""
    try:
        user_auth.logout_user()

        # Clear browser cookies to complete logout
        resp = make_response(redirect(url_for("index")))

        # Clear the theme cookie
        resp.set_cookie("theme", "", expires=0, samesite="Lax")

        # Clear the session cookie explicitly (Flask default session cookie name is 'session')
        resp.set_cookie("session", "", expires=0, samesite="Lax")

        # Clear any other persistent cookies the app might set
        # Add more cookie clearing here as needed

        return resp
    except Exception:
        logger.exception("Logout failed")
        # Fallback to simple redirect if cookie clearing fails
        return redirect(url_for("index"))

app.jinja_env.filters["highlight"] = highlight_term

# Security headers
@app.after_request
def add_security_headers(resp):
    # tighten defaults but allow blobs and media for previews
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "no-referrer-when-downgrade"

    # Allow inline styles only. Allow blob/data for images/media and frames used by preview modal.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: blob: https:; "
        "media-src 'self' data: blob: https:; "
        "frame-src 'self' data: blob: https:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    return resp

# Initialize DB
if not os.path.exists(config.EMAIL_CACHE_DIR):
    os.makedirs(config.EMAIL_CACHE_DIR, exist_ok=True)
    init_email_cache()

# Initialize model
detector = phishing_detector
detector.load_model("./phishing_mail_detect_model")

# Start background sync
sync_interval = int(os.getenv("SYNC_INTERVAL", "300"))
# Start background Gmail sync if user tokens with Gmail scope exist, or legacy token.json exists.
# This allows sync to work when users have logged in with Gmail access.
try:
    import user_auth
    import os

    # Check if any user has Gmail-authorized tokens
    user_tokens_dir = os.path.join(config.BASE_DIR, "cache", "user_tokens")
    gmail_authorized = False

    if os.path.exists(user_tokens_dir):
        for filename in os.listdir(user_tokens_dir):
            if filename.endswith('.json'):
                token_path = os.path.join(user_tokens_dir, filename)
                try:
                    import json
                    with open(token_path, 'r') as f:
                        token_data = json.load(f)
                        scopes = token_data.get('scopes', [])
                        if "https://www.googleapis.com/auth/gmail.readonly" in scopes:
                            gmail_authorized = True
                            break
                except Exception:
                    continue

    # Also check legacy token.json
    _gmail_token_path = os.path.join(config.BASE_DIR, "token.json")
    if not gmail_authorized and os.path.exists(_gmail_token_path):
        gmail_authorized = True

    if gmail_authorized:
        background_sync.start_continuous_sync(interval=sync_interval)  # type: ignore[attr-defined]
        logger.info("[SYNC] Gmail authorized; started continuous background sync")
    else:
        logger.info("[SYNC] No Gmail authorization found; skipping auto background sync until user logs in")
except Exception as e:
    logger.warning(f"[SYNC] failed to check Gmail authorization; skipping auto background sync: {e}")


def get_label_filter_from_request():
    """Safe helper for all routes."""
    v = request.args.get("label", "")
    if not v:
        return None
    return v.strip().lower()



# ===========================================================================
# UNIFIED OVERRIDE HELPER (used by rescan and other places)
# ===========================================================================
def _maybe_clear_manual_override_if_model_matches(msg_id: str, model_label: str | None) -> bool:
    """
    If a manual override exists for msg_id and its label strictly equals
    model_label (case-insensitive), remove the override and return True.
    Otherwise return False.
    Safe to call repeatedly; logs on exception but does not raise.
    """
    try:
        ov = email_cache.get_manual_override(msg_id)
        if not ov:
            return False
        manual = (ov.get("label") or "").strip().lower()
        model = (model_label or "").strip().lower()
        if manual and model and manual == model:
            try:
                email_cache.clear_manual_override(msg_id)
                logger.debug("[override_helper] cleared override for %s (model matched manual)", msg_id)
            except Exception:
                logger.exception("[override_helper] failed to clear override for %s", msg_id)
            return True
    except Exception:
        logger.exception("[override_helper] check failed for %s", msg_id)
    return False




@app.route("/")
def index(): 
    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 25))
    except ValueError:
        page = 1
        per_page = 25

    # always present
    query = request.args.get("q", "").strip()

    # always present
    label_filter = request.args.get("label", "").strip().lower()
    if label_filter == "":
        label_filter = None


    query = request.args.get("q", "").strip()
    total = 0

    if query:
        # normal search
        messages = email_cache.search_emails(query, page=page, per_page=per_page)
        total = email_cache.count_search_results(query)

        # pagination for search results
        if per_page > 0:
            total_pages = max(1, math.ceil(total / per_page))
            next_page = page + 1 if page < total_pages else None
            prev_page = page - 1 if page > 1 else None
        else:
            total_pages = 1
            next_page = None
            prev_page = None


    elif label_filter in ("safe", "phish", "maybephish", "unknown"):
        # LABEL-BASED FILTERING (uses manual override if present; override > model)
        all_cached = email_cache.get_cached_emails(limit=999999999)

        def effective_label_for_msg(m):
            try:
                msgid = m.get("id") or m.get("msg_id") or m.get("message_id")
                if msgid:
                    ov = email_cache.get_manual_override(msgid)
                    if ov and ov.get("label"):
                        return (ov.get("label") or "").strip().lower()
            except Exception:
                # DB/read error -> fall back to model label
                pass
            return (m.get("prediction_label") or "").strip().lower()

        if label_filter == "unknown":
            # Exclude "analyzing" emails from unknown filter - they should only appear in default view
            filtered = [m for m in all_cached if effective_label_for_msg(m) not in ("safe", "phish", "maybephish", "analyzing")]
        else:
            filtered = [m for m in all_cached if effective_label_for_msg(m) == label_filter]

        total = len(filtered)

        # manual pagination
        if per_page > 0:
            total_pages = max(1, math.ceil(total / per_page)) if total > 0 else 1
            start = (page - 1) * per_page
            end = start + per_page
            messages = filtered[start:end]
            next_page = page + 1 if page < total_pages else None
            prev_page = page - 1 if page > 1 else None
        else:
            # no pagination (show all)
            total_pages = 1
            messages = filtered
            next_page = None
            prev_page = None


    else:
        # Fetch ALL cached emails first (unpaginated)
        full_list = email_cache.get_cached_emails(limit=999999999)
        total = len(full_list)

        # === Apply default filter: hide PHISH + MAYBEPHISH ===
        if HIDE_PHISH_MAYBE_PHISH_INBOX and not query and not label_filter:
            def lbl(m):
                # prefer manual override label if present (user override is authoritative for UI/listing)
                try:
                    # cached emails may use 'id' or 'msg_id' or 'message_id' as key depending on loader
                    mid = m.get("id") or m.get("msg_id") or m.get("message_id")
                    if mid:
                        ov = email_cache.get_manual_override(mid)
                        if ov and ov.get("label"):
                            return (ov.get("label") or "").lower()
                except Exception:
                    # on any error, fall back to model label
                    pass
                return (m.get("prediction_label") or "").lower()


            # filter BEFORE pagination
            full_list = [m for m in full_list if lbl(m) not in ("phish", "maybephish")]

            total = len(full_list)

        # === Apply pagination AFTER filtering ===
        if per_page > 0:
            total_pages = max(1, math.ceil(total / per_page))
            start = (page - 1) * per_page
            end = start + per_page
            messages = full_list[start:end]
            next_page = page + 1 if page < total_pages else None
            prev_page = page - 1 if page > 1 else None
        else:
            total_pages = 1
            messages = full_list
            next_page = None
            prev_page = None


    # === GLOBAL LABEL TOTALS (accurate counts) ===
    try:
        # Get all emails for accurate counting
        all_emails = email_cache.get_cached_emails(limit=999999999) or []

        # Count by effective label (including manual overrides)
        counts = {
            "safe": 0,
            "phish": 0,
            "maybephish": 0,
            "unknown": 0,
            "analyzing": 0,
            "total": len(all_emails)
        }

        def effective_label(msg_dict):
            try:
                msgid = msg_dict.get("id") or msg_dict.get("msg_id") or msg_dict.get("message_id")
                if msgid:
                    ov = email_cache.get_manual_override(msgid)
                    if ov and ov.get("label"):
                        return (ov.get("label") or "").strip().lower()
            except Exception:
                pass
            return (msg_dict.get("prediction_label") or "").strip().lower()

        for email in all_emails:
            label = effective_label(email)
            if label in counts:
                counts[label] += 1
            else:
                # Any label not in our known categories goes to unknown
                counts["unknown"] += 1

        global_safe_total = counts.get('safe', 0)
        global_phish_total = counts.get('phish', 0)
        global_maybephish_total = counts.get('maybephish', 0)
        global_analyzing_total = counts.get('analyzing', 0)
        global_unknown_total = counts.get('unknown', 0)
        global_total_scanned = counts.get('total', 0)

        # Get Gmail account total for display
        global_gmail_total = None
        try:
            service = gmail_utils.get_service()
            if service:
                profile = service.users().getProfile(userId="me").execute()
                global_gmail_total = int(profile.get("messagesTotal", 0))
        except Exception:
            # Gmail total not available, that's ok
            global_gmail_total = None

    except Exception as e:
        logger.exception("[INDEX] Failed to calculate filter counts: %s", e)
        # Fallback
        global_total_scanned = email_cache.get_total_count()
        global_safe_total = 0
        global_phish_total = 0
        global_maybephish_total = 0
        global_analyzing_total = 0
        global_unknown_total = 0
        global_gmail_total = None

    # Normalize messages list so the inbox table reflects overrides
    for m in messages:
        try:
            msgid = m.get("id") or m.get("msg_id") or m.get("message_id")
            override = None
            if msgid:
                override = email_cache.get_manual_override(msgid)

            if override:
                # User override → display that in the inbox table
                m["prediction_label"] = (override.get("label") or "").strip().lower()
                m["prediction_score"] = float(override.get("score") or 1.0)

                model_expl = (m.get("explanation") or "") or ""
                m["explanation"] = (
                    f"Model explanation: {model_expl}\n"
                    f"This mail is manually classified as {m['prediction_label'].upper()} by the user."
                )
            else:
                # No override → keep model fields normalized
                m["prediction_label"] = (m.get("prediction_label") or "").strip().lower()
                m["prediction_score"] = m.get("prediction_score") or 0.0
                m["explanation"] = m.get("explanation") or ""

        except Exception:
            m["prediction_label"] = (m.get("prediction_label") or "").strip().lower()
            m["prediction_score"] = m.get("prediction_score") or 0.0
            m["explanation"] = m.get("explanation") or ""


    # Normalize the messages that will be rendered so templates keep using the same keys
    # Ensure each message dict advertises the effective/presented label/score/explanation
    for m in messages:
        try:
            msgid = m.get("id") or m.get("msg_id") or m.get("message_id")
            ov = None
            if msgid:
                ov = email_cache.get_manual_override(msgid)
            if ov:
                # override present -> surface it as the presented prediction fields
                m["prediction_label"] = (ov.get("label") or "").strip().lower()
                m["prediction_score"] = float(ov.get("score") or 1.0)
                model_expl = (m.get("explanation") or "") or ""
                m["explanation"] = f"Model explanation: {model_expl}\nThis mail is manually classified as {str(m['prediction_label']).upper()} by the user."
            else:
                # no override -> ensure fields exist and are normalized
                m["prediction_label"] = (m.get("prediction_label") or "").strip().lower()
                m["prediction_score"] = m.get("prediction_score") or 0.0
                m["explanation"] = m.get("explanation") or ""
        except Exception:
            # be resilient to any individual record errors
            m["prediction_label"] = (m.get("prediction_label") or "").strip().lower()
            m["prediction_score"] = m.get("prediction_score") or 0.0
            m["explanation"] = m.get("explanation") or ""


    # safety defaults in case pagination variables were not set above
    if 'next_page' not in locals():
        next_page = None
    if 'prev_page' not in locals():
        prev_page = None


    return render_template(
        "index.html",
        messages=messages,
        total=total,
        page=page,
        per_page=per_page,
        query=query,
        next_page=next_page,
        prev_page=prev_page,
        total_pages=total_pages,
        global_phish_total=global_phish_total,
        global_maybephish_total=global_maybephish_total,
        global_safe_total=global_safe_total,
        global_unknown_total=global_unknown_total,
        global_analyzing_total=global_analyzing_total,
        global_total_scanned=global_total_scanned,
        label_filter=get_label_filter_from_request(),
        show_phish_warning=SHOW_PHISH_WARNING,
        allow_dismiss_phish_warning=ALLOW_DISMISS_PHISH_WARNING,
    )

@app.route("/email_html/<msg_id>")
def email_html(msg_id):
    html = email_cache.get_email_html_body(msg_id)
    if not html:
        return "(No HTML body found)"

    # wrap to enforce blank target and inline links
    return f"""
    <!doctype html>
    <html>
    <head>
        <meta charset='utf-8'>
        <base target="_blank">
    </head>
    <body>
        {html}
    </body>
    </html>
    """


def env_bool(key, default=False):
    val = os.getenv(key, str(default)).lower()
    return val in ("1", "true", "yes", "on")

SHOW_LINK_TABLE = env_bool("SHOW_LINK_TABLE", True)
# Hide phish + maybephish by default unless disabled in .env
HIDE_PHISH_MAYBE_PHISH_INBOX = env_bool("HIDE_PHISH_MAYBE_PHISH_INBOX", True)
SHOW_PHISH_WARNING = env_bool("SHOW_PHISH_WARNING", True)
ALLOW_DISMISS_PHISH_WARNING = env_bool("ALLOW_DISMISS_PHISH_WARNING", True)


@app.route("/message/<msg_id>")
def message(msg_id):
    item = email_cache.get_cached_email(msg_id)
    if not item:
        abort(404, description="Message not found")

    html_body = item.get("html_body") or ""
    text_body = item.get("body") or ""

    if not html_body and text_body:
        html_body = f"<pre style='white-space: pre-wrap; font-family: Arial;'>{text_body}</pre>"

    attachments = item.get("attachments", [])
    # Ensure manual override is reflected (and annotate explanation)
    try:
        override = email_cache.get_manual_override(msg_id)
    except Exception:
        override = None

    # Ensure display_label/score/explanation reflect user override if present
    try:
        override = email_cache.get_manual_override(msg_id)
    except Exception:
        override = None

    if override:
        display_label = (override.get("label") or "").strip().lower()
        display_score = float(override.get("score") or 1.0)
        model_expl = (item.get("explanation") or "") or ""
        display_explanation = f"Model explanation: {model_expl}\nThis mail is manually classified as {str(display_label).upper()} by the user."
    else:
        display_label = (item.get("prediction_label") or "").strip().lower()
        display_score = item.get("prediction_score") or 0.0
        display_explanation = item.get("explanation") or ""

    # Build attachment analysis map keyed by attachmentId
    attachment_analysis_map: Dict[str, Dict[str, Any]] = {}
    vt_api = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
    vt_headers = {"x-apikey": vt_api} if vt_api else None
    if attachments:
        try:
            service = gmail_utils.get_service()
            if service:
                to_analyze = []
                id_order = []
                raw_bytes_by_id: Dict[str, bytes] = {}
                for a in attachments:
                    att_id = a.get("attachmentId")
                    fname = a.get("filename") or f"{att_id or 'file'}.bin"
                    if not att_id:
                        continue
                    try:
                        data = gmail_utils.get_attachment_data(service, "me", msg_id, att_id)
                    except Exception as e:
                        logger.warning(f"[MESSAGE] Failed to fetch attachment {att_id}: {e}")
                        data = None
                    
                    if data:
                        # Gmail API may return base64 string sometimes
                        if isinstance(data, str):
                            try:
                                data = base64.urlsafe_b64decode(data)
                            except Exception:
                                try:
                                    data = base64.b64decode(data)
                                except Exception:
                                    data = b""
                        raw_bytes_by_id[att_id] = data or b""
                        to_analyze.append({"filename": fname, "data": data or b""})
                        id_order.append(att_id)
                    else:
                        # Create placeholder for failed fetches so UI still shows analysis
                        raw_bytes_by_id[att_id] = b""
                        to_analyze.append({"filename": fname, "data": b""})
                        id_order.append(att_id)
                if to_analyze:
                    try:
                        analyzed = analyze_attachments(to_analyze)
                        files = analyzed.get("files", [])
                        for idx, fr in enumerate(files):
                            if idx < len(id_order):
                                attachment_analysis_map[id_order[idx]] = {
                                    "filename": fr.get("filename"),
                                    "is_safe": fr.get("is_safe"),
                                    "verdict": fr.get("verdict"),
                                    "risk_score": fr.get("risk_score", 0),
                                    "warnings": fr.get("warnings", []),
                                    "mime_type": fr.get("mime_type"),
                                }
                    except Exception as e:
                        logger.exception(f"[MESSAGE] Attachment analysis failed for {msg_id}: {e}")
                        # Still create basic entries for UI consistency
                        for idx, att_id in enumerate(id_order):
                            if att_id not in attachment_analysis_map:
                                attachment_analysis_map[att_id] = {
                                    "filename": to_analyze[idx].get("filename", "unknown"),
                                    "is_safe": True,
                                    "verdict": "error",
                                    "risk_score": 0,
                                    "warnings": [f"Analysis failed: {str(e)}"],
                                    "mime_type": "unknown",
                                }

                # VirusTotal hash-only lookup per attachment (optional)
                if vt_headers and raw_bytes_by_id:
                    for att_id, bts in raw_bytes_by_id.items():
                        if not bts:
                            continue
                        try:
                            sha256 = hashlib.sha256(bts).hexdigest()
                            url = f"https://www.virustotal.com/api/v3/files/{sha256}"
                            r = requests.get(url, headers=vt_headers, timeout=float(config.REQUEST_TIMEOUT))
                            if r.status_code == 200:
                                j = r.json()
                                attrs = (j.get("data") or {}).get("attributes") or {}
                                stats = attrs.get("last_analysis_stats") or {}
                                mal = int(stats.get("malicious") or 0)
                                susp = int(stats.get("suspicious") or 0)
                                harmless = int(stats.get("harmless") or 0)
                                undet = int(stats.get("undetected") or 0)
                                vt_verdict = "clean"
                                if mal > 0:
                                    vt_verdict = "malicious"
                                elif susp > 0:
                                    vt_verdict = "suspicious"
                                # attach under existing map entry or create minimal
                                entry = attachment_analysis_map.get(att_id) or {}
                                entry["vt"] = {
                                    "sha256": sha256,
                                    "stats": {
                                        "malicious": mal,
                                        "suspicious": susp,
                                        "harmless": harmless,
                                        "undetected": undet,
                                    },
                                    "verdict": vt_verdict,
                                }
                                attachment_analysis_map[att_id] = entry
                            elif r.status_code == 404:
                                # unknown file in VT
                                entry = attachment_analysis_map.get(att_id) or {}
                                entry["vt"] = {"sha256": sha256, "verdict": "unknown", "stats": {}}
                                attachment_analysis_map[att_id] = entry
                            else:
                                # other errors ignored gracefully
                                pass
                        except Exception:
                            # network or parse failure -> ignore
                            logger.debug("[MESSAGE] VT lookup failed for %s", att_id)
        except Exception as e:
            logger.exception("[MESSAGE] attachment analysis failed for %s: %s", msg_id, e)

    return render_template(
        "message.html",
        msg_id=msg_id,
        subject=item.get("subject"),
        sender=item.get("sender"),
        date=item.get("date"),
        body=text_body,
        html_body=html_body,
        raw=item.get("raw") or "",
        prediction_label=display_label,
        prediction_score=display_score,
        explanation=display_explanation,
        risk_links=item.get("risk_links", []),
        intel_links=item.get("intel_links", []),
        spf=item.get("spf_result", "unknown"),
        dkim=item.get("dkim_result", "unknown"),
        dmarc=item.get("dmarc_result", "unknown"),
        attachments=attachments,
        attachment_analysis_map=attachment_analysis_map,
        is_phish=(display_label in ("phish", "maybephish")),
        label_filter=get_label_filter_from_request(),
        show_link_table=SHOW_LINK_TABLE,
    )



@app.route("/raw/<msg_id>")
def raw_email(msg_id):
    raw = email_cache.get_email_raw(msg_id)
    if not raw:
        return "(No raw email found)", 404

    try:
        raw_text = raw.decode(errors="replace") if isinstance(raw, bytes) else raw
    except:
        raw_text = str(raw)

    return render_template("raw.html", msg_id=msg_id, raw=raw_text)


@app.route("/render/<msg_id>")
def render_email(msg_id):
    raw = email_cache.get_email_raw(msg_id)
    if not raw:
        return "Email not found", 404

    html_body = gmail_utils.extract_html_from_email(raw)
    if not html_body:
        html_body = "<i>No HTML content found in this message.</i>"

    return render_template("render.html", html_body=html_body, msg_id=msg_id)


@app.route("/original/<msg_id>")
def original_email(msg_id):
    view = request.args.get("view", "raw")
    raw = email_cache.get_email_raw(msg_id)
    if not raw:
        return "(No original email found)", 404

    # decoded text
    if view == "decoded":
        item = email_cache.get_cached_email(msg_id)
        text = item.get("body") if item else ""
        if not text:
            text = raw.decode(errors="replace",) if isinstance(raw, bytes) else str(raw)
        return render_template(
            "original.html",
            raw=text,
            msg_id=msg_id,
            view_type="decoded",
            html_body=None,
            label_filter=get_label_filter_from_request(),
        )

    # rendered HTML
    if view == "rendered":
        html = email_cache.get_email_html_body(msg_id)
        return render_template(
            "original.html",
            raw=raw,
            msg_id=msg_id,
            view_type="rendered",
            html_body=html,
            label_filter=get_label_filter_from_request(),
        )


    # raw view (default)
    try:
        raw_text = raw.decode(errors="replace") if isinstance(raw, bytes) else raw
    except:
        raw_text = str(raw)

    return render_template(
        "original.html",
        raw=raw_text,
        msg_id=msg_id,
        view_type="raw",
        label_filter=get_label_filter_from_request(),
        html_body=None,
    )




@app.route("/render_body/<msg_id>")
def render_body(msg_id):
    try:
        item = email_cache.get_cached_email(msg_id)
        if not item:
            return "Email not found", 404

        raw_encoded = item.get("raw") or ""
        if not raw_encoded:
            return "No raw data", 404

        raw_bytes = base64.urlsafe_b64decode(raw_encoded.encode("utf-8"))
        text_body, html_body = gmail_utils.extract_bodies_from_mime(raw_bytes)

        if not html_body and text_body:
            html_body = f"<pre style='white-space:pre-wrap;font-family:Arial;'>{text_body}</pre>"

        if not html_body:
            html_body = "<p>(No HTML content found)</p>"

        # Inject <base target="_blank">
        return f"<!doctype html><html><head><meta charset='utf-8'><base target='_blank'></head><body>{html_body}</body></html>"
    except Exception as e:
        logger.error(f"[RENDER_BODY] Failed to render body: {e}")
        return f"<p style='color:red;'>Failed to load HTML body: {e}</p>", 500


@app.route("/download/<msg_id>")
def download(msg_id):
    """
    Download a Gmail message as a .eml file.
    Handles both cached messages and live Gmail API fetch.
    """
    try:
        cached = email_cache.get_email_by_id(msg_id)
        if cached and cached.get("raw"):
            raw_encoded = cached["raw"]
        else:
            service = gmail_utils.get_service()
            if not service:
                return "Error: Gmail service unavailable.", 500

            message = service.users().messages().get(
                userId="me", id=msg_id, format="raw"
            ).execute()
            raw_encoded = message.get("raw", "")
            if not raw_encoded:
                return "Error: No raw data found for message.", 404

        decoded_bytes = gmail_utils.decode_base64_data(raw_encoded)
        if not decoded_bytes:
            return "Error: Unable to decode message data.", 500

        response = make_response(decoded_bytes)
        response.headers.set("Content-Type", "message/rfc822")
        response.headers.set("Content-Disposition", f"attachment; filename={msg_id}.eml")
        return response

    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"[DOWNLOAD] Failed to download message {msg_id}: {e}\n{tb}")
        return f"Error downloading message: {e}", 500




@app.route("/download_attachment/<msg_id>/<attachment_id>")
def download_attachment(msg_id, attachment_id):
    """
    Download attachment by Gmail attachmentId.
    Uses Gmail API live fetch.
    """
    try:
        service = gmail_utils.get_service()
        if not service:
            return "Gmail service unavailable", 500

        # Fetch the cached email for filename info
        item = email_cache.get_cached_email(msg_id)
        att_meta = None
        if item and item.get("attachments"):
            for a in item["attachments"]:
                if a.get("attachmentId") == attachment_id:
                    att_meta = a
                    break

        data = gmail_utils.get_attachment_data(service, "me", msg_id, attachment_id)
        if not data:
            return "Attachment not found or empty", 404

        filename = att_meta.get("filename") if att_meta else f"{attachment_id}.bin"
        mime = att_meta.get("mimeType") if att_meta else "application/octet-stream"

        response = make_response(data)
        response.headers.set("Content-Type", mime)
        response.headers.set("Content-Disposition", f"attachment; filename={filename}")
        return response
    except Exception as e:
        logger.error(f"[ATTACH-DL] Failed {attachment_id}: {e}")
        return f"Error downloading attachment: {e}", 500

@app.route("/preview_attachment/<msg_id>/<path:attachment_id>")
def preview_attachment(msg_id, attachment_id):
    """
    Preview Gmail attachments using PDF-style viewer for text files and documents.
    """
    from attachment_preview import preview_attachment as preview_func
    return preview_func(msg_id, attachment_id, gmail_utils, email_cache)




# --- Lightweight rate limit for /api/rescan --------------------------------
_RES_CAN = {}
def _rate_limit(key, per=20, burst=3):
    # at most 'burst' calls every 'per' seconds per key
    now = time.time()
    bucket = _RES_CAN.get(key, [])
    bucket = [t for t in bucket if now - t < per]
    if len(bucket) >= burst:
        return False
    bucket.append(now)
    _RES_CAN[key] = bucket
    return True



@app.route("/api/sync_status")
def sync_status():
    return jsonify(background_sync.get_sync_status())  # type: ignore[attr-defined]


@app.route("/api/force_sync", methods=["POST"])
def force_sync():
    # Check if user is logged in (which now includes Gmail authorization)
    if not user_auth.is_logged_in():
        return jsonify({"ok": False, "error": "User not logged in"}), 401

    user_email = session.get('user_email')
    try:
        # Pass user email to sync function so it can use the correct token
        threading.Thread(target=lambda: background_sync.force_sync_once(user_email), daemon=True).start()  # type: ignore[attr-defined]
        return jsonify({"ok": True})
    except Exception as e:
        logger.exception("Failed to start force sync")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/incremental_sync", methods=["POST"])
def incremental_sync():
    # Check if user is logged in (which now includes Gmail authorization)
    if not user_auth.is_logged_in():
        return jsonify({"ok": False, "error": "User not logged in"}), 401

    user_email = session.get('user_email')
    try:
        # Start incremental sync for the current user
        threading.Thread(target=lambda: background_sync._sync_incremental(user_email), daemon=True).start()  # type: ignore[attr-defined]
        return jsonify({"ok": True, "message": "Incremental sync started"})
    except Exception as e:
        logger.exception("Failed to start incremental sync")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/sync_state")
def sync_state():
    # Check if user is logged in
    if not user_auth.is_logged_in():
        return jsonify({"error": "User not logged in"}), 401

    user_email = session.get('user_email')
    try:
        # Get current sync status and user's sync state
        status = background_sync.get_sync_status()  # type: ignore[attr-defined]
        if user_email:
            import background_sync as bs
            user_state = bs._load_sync_state(user_email)  # type: ignore[attr-defined]
            status["user_state"] = user_state

        return jsonify(status)
    except Exception as e:
        logger.exception("Failed to get sync state")
        return jsonify({"error": str(e)}), 500


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})


@app.route("/api/rescan/<msg_id>", methods=["POST"])
def rescan_email(msg_id):
    """
    Re-run full Gmail message analysis pipeline and return updated label (safe, phish, maybephish).
    Uses analyze_email_links_and_content early to short-circuit empty emails.

    Behavior improvements:
      - Validates msg_id.
      - Runs process_single_email in a background thread and waits up to 8s for completion.
      - If processing completes within timeout, return updated results.
      - If processing continues longer, return 202 with started=True so UI may poll/reload.
    """
    # Basic validation
    if not msg_id or not str(msg_id).strip():
        return jsonify({"ok": False, "error": "Missing message id"}), 404

    # rate-limit per message id (avoid abuse)
    if not _rate_limit(f"rescan:{msg_id}", per=20, burst=3):
        return jsonify({"ok": False, "error": "Rate limit exceeded"}), 429

    item = email_cache.get_cached_email(msg_id)
    if not item:
        return jsonify({"ok": False, "error": "Email not found"}), 404

    try:
        raw_data = item.get("raw", "")
        if raw_data:
            # try to decode but tolerate non-urlsafe encodings
            try:
                raw_bytes = base64.urlsafe_b64decode(raw_data.encode("utf-8"))
            except Exception:
                try:
                    raw_bytes = base64.b64decode(raw_data.encode("utf-8"))
                except Exception:
                    raw_bytes = b""
            if raw_bytes:
                text_body, html_body = gmail_utils.extract_bodies_from_mime(raw_bytes)
                if html_body:
                    cleaned_text, urls = gmail_utils.clean_html_for_text(html_body)
                elif text_body:
                    cleaned_text, urls = gmail_utils.clean_html_for_text(text_body)
                else:
                    cleaned_text, urls = "", []
                item["body"] = f"{item.get('subject','')}. {cleaned_text}"
                item["urls"] = urls
                item["html_body"] = html_body
            else:
                item["urls"] = item.get("urls", []) or []
        else:
            item["urls"] = item.get("urls", []) or []

        # Run early analyzer to short-circuit truly empty messages
        try:
            early = intelligence_heuristics_email_analysis.analyze_email_links_and_content(
                item.get("id") or item.get("msg_id"),
                item.get("subject", "") or "",
                item.get("body", "") or "",
                item.get("html_body", "") or "",
                item.get("sender") or item.get("from") or ""
            )
            early_expl = (early.get("explanation") or "").strip() or ""
            if early_expl.upper().startswith("NO TEXT DETECTED"):
                # Let background processing update cache consistently, but attempt synchronous run first
                t = threading.Thread(target=background_sync.process_single_email, args=(item,), daemon=True)
                t.start()
                t.join(timeout=8)
                updated = email_cache.get_cached_email(msg_id)
                if updated is not None:
                    # --- STRICT-MATCH AUTO-CLEAR OVERRIDE ---
                    try:
                        _maybe_clear_manual_override_if_model_matches(msg_id, updated.get("prediction_label"))
                        updated = email_cache.get_cached_email(msg_id)
                    except Exception:
                        logger.exception("[RESCAN] auto-clear override check failed for %s", msg_id)

                    updated_dict = cast(Dict[str, Any], updated)
                    return jsonify({
                        "ok": True,
                        "label": updated_dict.get("prediction_label"),
                        "score": updated_dict.get("prediction_score"),
                        "reason": updated_dict.get("explanation"),
                        "risk_links": updated_dict.get("risk_links", [])
                    })

                # if not updated yet, return started
                return jsonify({"ok": True, "started": True}), 202
        except Exception:
            # proceed normally if early analyzer fails
            logger.exception("[RESCAN] early analyzer failed for %s", msg_id)

        logger.info(f"[RESCAN] {msg_id}: re-extracted {len(item.get('urls') or [])} URLs")

        # Run processing but don't block longer than a short timeout
        thread = threading.Thread(target=background_sync.process_single_email, args=(item,), daemon=True)
        thread.start()
        thread.join(timeout=8)  # wait briefly for fast updates

        updated = email_cache.get_cached_email(msg_id)
        if updated is not None and cast(Dict[str, Any], updated).get("prediction_label") is not None:
            # --- STRICT-MATCH AUTO-CLEAR OVERRIDE ---
            try:
                _maybe_clear_manual_override_if_model_matches(msg_id, updated.get("prediction_label"))
                updated = email_cache.get_cached_email(msg_id)
            except Exception:
                logger.exception("[RESCAN] auto-clear override check failed for %s", msg_id)

            updated_dict = cast(Dict[str, Any], updated)
            return jsonify({
                "ok": True,
                "label": updated_dict.get("prediction_label"),
                "score": updated_dict.get("prediction_score"),
                "reason": updated_dict.get("explanation"),
                "risk_links": updated_dict.get("risk_links", [])
            })


        # Still processing or no immediate update — return accepted and let UI poll / reload
        return jsonify({"ok": True, "started": True}), 202

    except Exception as e:
        logger.error(f"[RESCAN] Failed for {msg_id}: {e}", exc_info=True)
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/override_label/<msg_id>", methods=["POST"])
def api_override_label(msg_id):
    """
    Set a user manual override for a message.
    Accepts JSON: { "label": "safe" | "phish", "score": <float, optional> }
    Returns canonical JSON on success: { "status":"ok", "msg_id":..., "override": { "label":..., "score":..., "ts":... } }
    """
    data = request.get_json(force=True, silent=True) or {}
    label_raw = (data.get("label") or "")
    score_raw = data.get("score", 1.0)

    # normalize
    label = (label_raw or "").strip().lower()
    try:
        score = float(score_raw or 1.0)
    except Exception:
        score = 1.0

    # Accept only the two allowed manual override labels
    if label not in ("safe", "phish"):
        return jsonify({"ok": False, "error": "invalid label; allowed values: safe, phish"}), 400

    try:
        # persist override
        email_cache.set_manual_override(msg_id, label, score)
        # read back what was stored (best-effort)
        ov = email_cache.get_manual_override(msg_id) or {}
        return jsonify({
            "ok": True,
            "status": "ok",
            "msg_id": msg_id,
            "override": {
                "label": ov.get("label") or label,
                "score": ov.get("score") if ov.get("score") is not None else score,
                "ts": ov.get("ts")
            }
        })
    except Exception as e:
        logger.exception("[api_override_label] failed to set override for %s: %s", msg_id, e)
        return jsonify({"ok": False, "error": "failed to set override"}), 500



@app.route("/api/clear_override/<msg_id>", methods=["POST"])
def api_clear_override(msg_id):
    try:
        email_cache.clear_manual_override(msg_id)
        return jsonify({"status": "ok", "msg_id": msg_id})
    except Exception as e:
        logger.exception("[api_clear_override] failed to clear override for %s: %s", msg_id, e)
        return jsonify({"error": "failed to clear override"}), 500



# ===== Lightweight live status endpoint used by the UI polling =====
@app.route("/api/live_status")
def api_live_status():
    """
    Return small status for UI:
      { status: "idle"|"syncing"|"classifying", status_text: "...", total_mails: N, gmail_total: M }
    This function is resilient if background_sync or email_cache internals are missing.

    For concurrent sync, show more detailed status based on sync mode.
    """
    try:
        # background_sync doesn't expose get_state(); infer from sync_status
        try:
            st = background_sync.get_sync_status() or {}
            mode = st.get("mode", "")
            is_running = st.get("running", False)

            if is_running:
                if mode == "concurrent":
                    state = "syncing"
                    status_text = "Concurrent sync active"
                else:
                    state = "syncing"
                    status_text = "Syncing..."
            else:
                state = "idle"
                status_text = ""
        except Exception:
            state = "idle"
            status_text = ""

        try:
            cached_total = int(email_cache.get_total_count())
        except Exception:
            cached_total = 0

        # Get Gmail account total (if available)
        gmail_total = None
        try:
            service = gmail_utils.get_service()
            if service:
                profile = service.users().getProfile(userId="me").execute()
                gmail_total = int(profile.get("messagesTotal", 0))
        except Exception:
            # Gmail total not available, that's ok
            gmail_total = None

        return jsonify({
            "status": state or "idle",
            "status_text": status_text,
            "total_mails": cached_total,
            "gmail_total": gmail_total
        })
    except Exception as e:
        logger.exception("[api_live_status] failed: %s", e)
        return jsonify({"status": "idle", "status_text": "", "total_mails": 0, "gmail_total": None})


@app.route("/api/filter_counts")
def api_filter_counts():
    """
    Return accurate counts for each filter category:
      { safe: N, phish: N, maybephish: N, unknown: N, analyzing: N, total: N }
    """
    try:
        # Get all emails for accurate counting (not sample)
        all_emails = email_cache.get_cached_emails(limit=999999999) or []

        # Count by effective label (including manual overrides)
        counts = {
            "safe": 0,
            "phish": 0,
            "maybephish": 0,
            "unknown": 0,
            "analyzing": 0,
            "total": len(all_emails)
        }

        def effective_label(msg_dict):
            try:
                msgid = msg_dict.get("id") or msg_dict.get("msg_id") or msg_dict.get("message_id")
                if msgid:
                    ov = email_cache.get_manual_override(msgid)
                    if ov and ov.get("label"):
                        return (ov.get("label") or "").strip().lower()
            except Exception:
                pass
            return (msg_dict.get("prediction_label") or "").strip().lower()

        for email in all_emails:
            label = effective_label(email)
            if label in counts:
                counts[label] += 1
            else:
                # Any label not in our known categories goes to unknown
                counts["unknown"] += 1

        return jsonify(counts)
    except Exception as e:
        logger.exception("[api_filter_counts] failed: %s", e)
        return jsonify({
            "safe": 0,
            "phish": 0,
            "maybephish": 0,
            "unknown": 0,
            "analyzing": 0,
            "total": 0
        })


# ===== Lightweight inbox data endpoint for incremental refresh =====
@app.route("/api/inbox_data")
def api_inbox_data():
    """
    Returns minimal JSON for the inbox view. Accepts the same query params as index:
      page, per_page, q, label
    Response:
      {
        total: N,
        total_pages: P,
        page: current_page,
        messages: [ { id, subject, sender, date, prediction_label, url } ],
        prev_url: "...", next_url: "...",
        status: "idle"|"syncing"|"classifying",
        status_text: "..."
      }
    """
    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 25))
    except Exception:
        page = 1
        per_page = 25
    q = (request.args.get("q") or "").strip()
    label = (request.args.get("label") or "").strip()

    # Default hide phish/maybephish unless explicitly filtered or searched
    # Include "analyzing" emails so users can see them immediately
    if HIDE_PHISH_MAYBE_PHISH_INBOX and not q and not label:
        label = "safe,unknown,analyzing"
    # Fetch paged inbox data and render JSON (no forced exception)
    # basedpyright: email_cache.fetch_messages expects str for q/label.
    # This route allows q/label to be omitted; normalize to empty strings.
    result = email_cache.fetch_messages(page=page, per_page=per_page, q=q, label=label)
    messages = result.get("items", [])
    filtered_total = result.get("total", 0)
    total_pages = max(1, math.ceil(filtered_total / per_page)) if per_page and per_page > 0 else 1

    # Ensure each message has a url
    for m in messages:
        if "url" not in m and m.get("id"):
            mid = cast(str, m.get("id"))
            m["url"] = url_for("message", msg_id=mid)

    # build prev/next urls preserving q/label/per_page
    def make_url(p):
        if not p:
            return None
        args = {"page": p, "per_page": per_page}
        if q: args["q"] = q
        # Do not include implicit default filter in the URL
        if label and label != "safe,unknown":
            args["label"] = label
        return url_for("index", **args)

    prev_url = make_url(page - 1) if page > 1 else None
    next_url = make_url(page + 1) if page < total_pages else None

    # include live status
    try:
        st = background_sync.get_sync_status() or {}  # type: ignore[attr-defined]
        state = "syncing" if st.get("running") else "idle"
    except Exception:
        state = "idle"
    status_text = ""
    if state == "syncing":
        status_text = "Syncing..."
    elif state == "classifying":
        status_text = "Classifying..."

    # total = filtered total for current view
    return jsonify({
        "total": filtered_total,
        "total_pages": total_pages,
        "page": page,
        "messages": messages,
        "prev_url": prev_url,
        "next_url": next_url,
        "status": state,
        "status_text": status_text
    })


# --- THEME HANDLERS ---

@app.before_request
def load_theme_from_cookie():
    """
    Ensures every request knows the correct theme before template render.
    Priority:
        1. Cookie "theme"
        2. Session["theme"]
        3. Default = light
    """
    theme = request.cookies.get("theme") or session.get("theme", "light")
    session["theme"] = theme
    g.theme = theme  # for Jinja templates


# --- Global access control ---------------------------------------------------
# Protect all pages by default, except login/callback/health and static assets.
@app.before_request
def require_login_for_protected_routes():
    """Redirect unauthenticated users to /login for protected routes."""
    try:
        # Flask uses the special endpoint name 'static' for /static/*
        if request.endpoint == "static":
            return None

        path = request.path or ""
        # Allow auth endpoints and health check
        if path in ("/login", "/login/start", "/auth/callback", "/api/health"):
            return None

        # If already logged in, allow
        if user_auth.is_logged_in():
            return None

        # Redirect to login with next parameter
        return redirect(url_for("login", next=request.url))
    except Exception:
        # Fail open to avoid taking down the app if something unexpected happens
        return None


@app.context_processor
def inject_theme():
    """
    Makes `theme` available in all templates as {{ theme }}.
    """
    return {"theme": getattr(g, "theme", "light")}


@app.route("/api/get_theme", methods=["GET"])
def get_theme():
    theme = session.get("theme", "light")
    return jsonify({"theme": theme})


@app.route("/api/set_theme", methods=["POST"])
def set_theme():
    data = request.get_json(silent=True) or {}
    theme = data.get("theme", "light")
    session["theme"] = theme

    resp = make_response(jsonify({"ok": True, "theme": theme}))
    resp.set_cookie("theme", theme, samesite="Lax", max_age=60*60*24*365)  # 1-year persist
    return resp


if __name__ == "__main__":
    logger.info("Starting app...")
    app.run(host="0.0.0.0", port=8080, debug=False)
