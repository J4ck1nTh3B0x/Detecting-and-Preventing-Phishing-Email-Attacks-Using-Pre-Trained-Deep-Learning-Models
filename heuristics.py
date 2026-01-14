"""
heuristics.py

Hybrid phishing detection with optional "model-only" diagnostic flag.
SOC edition adds fusion with VT/GSB intel and SPF/DKIM/DMARC signals.

"""

import os
import re
import logging
import unicodedata
import difflib
import requests
import socket
from typing import Tuple, List, Dict, Optional, Set, Any
from urllib.parse import urlparse
from dotenv import load_dotenv
import email_cache
from gmail_utils import clean_html_for_text
import csv
from pathlib import Path

# Import brandlist helpers from root; keep no-op fallback if missing
try:
    # Try to import from the intelligence module first
    from intelligence.brandlist import (
        get_known_domains,
        get_known_brands,
        get_brand_for_domain,
        is_brand_domain,
        find_similar_brands
    )
except ImportError as e:
    logger = logging.getLogger("heuristics")
    logger.warning(f"[HEUR] Failed to import brandlist module: {e}")
    
    # Fallback implementations
    def get_known_brands():
        return ["brand1", "brand2", "brand3"]  # Return a list of known brands
        
    def get_known_domains():
        return []
        
    def get_brand_for_domain(domain: str) -> Optional[str]:
        return None
        
    def is_brand_domain(domain: str) -> bool:
        return False
        
    def find_similar_brands(query: str, threshold: float = 0.8):
        return []
    
    # Define domain_from_url for the fallback case
    def domain_from_url(u: str) -> str:
        try:
            if not u.startswith(('http://', 'https://')):
                u = 'http://' + u
            domain = urlparse(u).netloc
            # Remove port if present
            domain = domain.split(":")[0]
            # Remove www. prefix
            if domain.startswith("www."):
                domain = domain[4:]
            return domain.lower()
        except Exception:
            return ""

# Import file analyzer
from file_analyzer import analyze_attachments

try:
    from intelligence.brandlist import (
        get_known_brands,
        get_known_domains,
        get_brand_for_domain,
        is_brand_domain,
        find_similar_brands
    )
    
    def domain_from_url(u: str) -> str:
        """Extract domain from URL."""
        if not u:
            return ""
        # Remove protocol and path
        domain = u.split("://")[-1].split("/")[0]
        # Remove port if present
        domain = domain.split(":")[0]
        # Remove www. prefix
        if domain.startswith("www."):
            domain = domain[4:]
        return domain.lower()
        
except Exception as e:
    logger.warning(f"[HEUR] Failed to load brandlist module: {e}")
    
    # Fallback implementations
    def get_known_domains():
        return []

    def get_known_brands():
        return []
        
    def get_brand_for_domain(domain: str) -> Optional[str]:
        return None
        
    def is_brand_domain(domain: str) -> bool:
        return False
        
    def find_similar_brands(query: str, threshold: float = 0.8) -> List[Tuple[str, float]]:
        return []
        
    def domain_from_url(u: str) -> str:
        try:
            p = urlparse(u if u.startswith("http") else "http://" + u)
            return (p.hostname or "").lower()
        except Exception:
            return ""

# Initialize logger
logger = logging.getLogger("heuristics")

# Initialize known brands cache
_known_brands_cache = set()

def _update_known_brands_cache():
    """Update the known brands cache from the brand list"""
    global _known_brands_cache
    try:
        _known_brands_cache = set(get_known_brands() or [])
    except Exception as e:
        logger.warning(f"Failed to update known brands cache: {e}")
        _known_brands_cache = set()

# Initialize the cache on import
_update_known_brands_cache()
load_dotenv()

# config
HOMOGRAPH_SIMILARITY_THRESHOLD = float(os.getenv("HOMOGRAPH_SIMILARITY_THRESHOLD", "0.80"))
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "5.0"))
# If STRICT_MODEL_ONLY set to true, heuristics will be skipped entirely (useful for diagnostics)
STRICT_MODEL_ONLY_ENV = os.getenv("STRICT_MODEL_ONLY", "false").lower() in ("true", "1", "yes")

# Optional: prefer tldextract for robust domain extraction if available
try:
    import tldextract
    _HAS_TLDEXTRACT = True
except Exception:
    _HAS_TLDEXTRACT = False

# Import brandlist helpers from root; keep no-op fallback if missing
try:
    # Try to import from the intelligence module first
    from intelligence.brandlist import (
        get_known_domains,
        get_known_brands,
        get_brand_for_domain,
        is_brand_domain,
        find_similar_brands
    )
    
    def domain_from_url(u: str) -> str:
        """Extract domain from URL."""
        if not u:
            return ""
        # Remove protocol and path
        domain = u.split("://")[-1].split("/")[0]
        # Remove port if present
        domain = domain.split(":")[0]
        # Remove www. prefix
        if domain.startswith("www."):
            domain = domain[4:]
        return domain.lower()
        
except Exception as e:
    logger.warning(f"[HEUR] Failed to load brandlist module: {e}")
    
    # Fallback implementations
    def get_known_domains():
        return []

    def get_known_brands():
        return []
        
    def get_brand_for_domain(domain: str) -> Optional[str]:
        return None
        
    def is_brand_domain(domain: str) -> bool:
        return False
        
    def find_similar_brands(query: str, threshold: float = 0.8) -> List[Tuple[str, float]]:
        return []
        
    def domain_from_url(u: str) -> str:
        try:
            p = urlparse(u if u.startswith("http") else "http://" + u)
            return (p.hostname or "").lower()
        except Exception:
            return ""

# threat intel enrich function (optional)
try:
    from threat_intel import intel_enrich, resolve_brand
except Exception:
    # intel_enrich fallback that returns empty results
    def intel_enrich(urls: List[str]) -> List[Dict]:
        return []

    # optional helper to ask intel about single domain/url
    def resolve_brand(domain: str) -> Optional[str]:
        return None

def _get_brands() -> List[str]:
    """Get list of known brands, always fresh from the live-updating cache."""
    try:
        return get_known_brands()
    except Exception as e:
        logger.warning(f"[HEUR] Failed to load brands: {e}")
        return []

def _get_domains() -> Set[str]:
    """Get set of known domains, always fresh from the live-updating cache."""
    try:
        return set(get_known_domains())
    except Exception as e:
        logger.warning(f"[HEUR] Failed to load domains: {e}")
        return set()

_whitelist_emails = None
_whitelist_mtime = None

def _get_whitelist_emails() -> set:
    global _whitelist_emails
    global _whitelist_mtime
    if _whitelist_emails is not None:
        try:
            base_dir = Path(__file__).resolve().parent
            wl_path = base_dir / "intelligence" / "cache" / "whitelist.csv"
            if wl_path.stat().st_mtime == _whitelist_mtime:
                return _whitelist_emails
        except Exception:
            pass

    try:
        base_dir = Path(__file__).resolve().parent
        wl_path = base_dir / "intelligence" / "cache" / "whitelist.csv"
        emails = set()
        if wl_path.exists():
            with wl_path.open("r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    e = (row.get("Email") or row.get("email") or "").strip().lower()
                    if e:
                        emails.add(e)
        _whitelist_emails = emails
        try:
            _whitelist_mtime = wl_path.stat().st_mtime
        except Exception:
            _whitelist_mtime = None
        return _whitelist_emails
    except Exception:
        _whitelist_emails = set()
        _whitelist_mtime = None
        return _whitelist_emails

# ----------------- Utility helpers -----------------
def extract_domain_from_email(addr: str) -> str:
    """Extract the domain portion from an email address."""
    if not addr:
        return ""
    m = re.search(r"@([A-Za-z0-9\.-]+)$", addr)
    return m.group(1).lower() if m else ""

def decode_punycode(label: str) -> str:
    """Decode punycode/IDN labels."""
    try:
        return label.encode("ascii").decode("idna")
    except Exception:
        return label

def label_contains_nonascii(label: str) -> bool:
    """Detect non-ASCII characters in a label (potential IDN)."""
    return any(ord(c) > 127 for c in (label or ""))

def skeleton(text: str) -> str:
    """
    Normalize text for visual homograph comparison:
    - NFKC normalization
    - remove diacritics
    - lowercase
    """
    if not text:
        return ""
    try:
        t = unicodedata.normalize("NFKC", text)
        t = ''.join(ch for ch in unicodedata.normalize("NFKD", t) if unicodedata.category(ch) != "Mn")
        return t.lower()
    except Exception:
        return text.lower()

def similarity(a: str, b: str) -> float:
    """Return similarity ratio (0–1) using difflib (robust fallback)."""
    try:
        return difflib.SequenceMatcher(None, a, b).ratio()
    except Exception:
        return 0.0

def extract_domain_host(url: str) -> str:
    """
    Extract and validate the host/domain for security checks.
    Handles IDN, punycode, and attempts to detect domain spoofing.
    """
    if not url:
        return ""
        
    # Clean and normalize URL
    url = url.strip().lower()
    
    # Handle common obfuscation techniques
    if 'hxxp' in url:
        url = url.replace('hxxp', 'http')
    
    # Extract domain using domain_from_url if available
    try:
        d = domain_from_url(url)
        if d and len(d) > 1:  # Basic validation
            return d
    except Exception:
        pass

    # fallback robust parsing
    try:
        p = urlparse(url if re.match(r"^[a-zA-Z]+://", url) else "http://" + url)
        hostname = (p.hostname or "").lower()
        # normalize tracking prefixes (e.g., 52.email.stripe.com → stripe.com)
        parts = hostname.split(".")
        if len(parts) >= 3 and parts[-2] in _known_brands_cache:
            hostname = ".".join(parts[-2:])

        if not hostname:
            return ""
        if _HAS_TLDEXTRACT:
            ext = tldextract.extract(hostname)
            if ext.registered_domain:
                # return full hostname (we'll still reference subdomain/labels later)
                return hostname
        return hostname
    except Exception:
        return ""

def _registered_domain(hostname: str) -> str:
    """Return the registered (effective second-level) domain for hierarchy checks."""
    if not hostname:
        return ""
    if _HAS_TLDEXTRACT:
        ext = tldextract.extract(hostname)
        return ext.registered_domain or hostname
    # naive fallback: take last two labels
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

def is_reachable(url: str) -> bool:
    """
    Lightweight reachability test using HEAD → fallback GET.
    Does NOT follow dangerous redirects and never raises exceptions.
    """
    if not url:
        return False

    try:
        if not re.match(r"^[a-zA-Z]+://", url):
            url = "https://" + url

        headers = {"User-Agent": "Mozilla/5.0 (HeuristicsReachability/1.0)"}

        # First try HEAD
        r = requests.head(url, allow_redirects=True, timeout=REQUEST_TIMEOUT, verify=True, headers=headers)
        if r.status_code < 400:
            return True

        # Some servers block HEAD
        if r.status_code in (403, 405) or str(r.status_code).startswith("5"):
            g = requests.get(url, allow_redirects=True, timeout=REQUEST_TIMEOUT, verify=True, headers=headers)
            return g.status_code < 400

        return False

    except Exception:
        return False

# ----------------- Homograph / impersonation checks -----------------
def _try_resolve_brand_with_intel(hostname: str) -> Optional[str]:
    """
    Ask threat intel (if available) about a hostname or its registered domain.
    Returns canonical brand name string if intel claims impersonation/association,
    otherwise None.
    """
    if not hostname:
        return None
    try:
        # prefer using resolve_brand if threat_intel exposes it
        if 'resolve_brand' in globals() and callable(globals().get('resolve_brand')):
            try:
                b = resolve_brand(hostname)
                if b:
                    return b
            except Exception:
                pass

        # as fallback, call intel_enrich on the hostname as a URL
        intel = intel_enrich([hostname])
        if not intel:
            return None
        entry = intel[0]
        # intel may include a canonical brand field; check common keys
        possible_brand_fields = ("brand", "canonical_brand", "associated_brand", "intel_brand", "name")
        for k in possible_brand_fields:
            if entry.get(k):
                return entry.get(k)
        # some intel returns 'impersonates' or 'related_to'
        for k in ("impersonates", "related_to", "associated_with"):
            if entry.get(k):
                return entry.get(k)
        # nothing authoritative
        return None
    except Exception:
        return None


def _resolve_brand_fuzzy(hostname: str, labels_decoded: List[str]) -> Optional[str]:
    """
    Local fuzzy resolution:
    - Searches known brands in hostname (substring & label checks).
    - Uses skeleton & similarity to avoid tiny/noise matches.
    - Avoids matching on extremely short brands (<3 chars) unless explicit substring match.
    """
    if not hostname:
        return None
    hostname_lower = hostname.lower()

    # prefer exact substring match for brands of reasonable length
    for brand in _known_brands_cache:
        if not brand or len(brand) < 2:
            continue
        # require brand length >=3 for similarity checks to avoid noise
        # must match full label or clear substring, not single-char noise
        if brand in hostname_lower and len(brand) >= 3:
            return brand

    # check each label (subdomain/second-level)
    for lbl in labels_decoded:
        s_lbl = skeleton(lbl)
        for brand in _known_brands_cache:
            if not brand:
                continue
            s_brand = skeleton(brand)
            # avoid matching on extremely short brands <3 by similarity
            if len(s_brand) < 3:
                continue
            if similarity(s_lbl, s_brand) >= HOMOGRAPH_SIMILARITY_THRESHOLD:
                return brand
    return None


def check_idn_homograph(domain: str) -> Tuple[bool, str, Optional[str]]:
    """
    Detect IDN homographs, brand-modifier impersonations, and return:
      (is_impersonation_like, note, impersonated_brand_or_None)

    Approach:
    1. Split domain into labels and decode punycode labels.
    2. If non-ASCII present -> possible IDN homograph.
    3. Try authority intel resolution first (API).
    4. Substring detection of known brands in domain (brand-modifier).
    5. Visual similarity on main label(s) using skeleton() and similarity().
    6. Consider registered domain + subdomain hierarchy to detect subdomain impersonation.
    """
    if not domain:
        return False, "", None

    labels = domain.split(".")
    decoded = []
    for l in labels:
        try:
            decoded.append(decode_punycode(l))
        except Exception:
            decoded.append(l)

    # 0. canonical registered domain and label breakdown
    registered = _registered_domain(domain)
    main_label = decoded[-2] if len(decoded) >= 2 else (decoded[0] if decoded else "")
    sublabels = decoded[:-2] if len(decoded) >= 3 else decoded[:-1] if len(decoded) >= 2 else []

    # 1. Non-ASCII / IDN homograph detection
    if any(label_contains_nonascii(l) for l in decoded):
        return True, "domain contains non-ASCII characters (possible IDN homograph)", None

    # 2. Ask intel (API-first)
    try:
        intel_brand = _try_resolve_brand_with_intel(domain)
        if intel_brand:
            return True, f"domain appears to impersonate '{intel_brand}' (resolved via intel API)", intel_brand
        # also ask about the registered domain if different
        if registered and registered != domain:
            intel_brand = _try_resolve_brand_with_intel(registered)
            if intel_brand:
                return True, f"registered domain {registered} appears to impersonate '{intel_brand}' (resolved via intel API)", intel_brand
    except Exception:
        # keep going to heuristics if intel is unavailable
        pass

    # 3. Brand-modifier pattern: e.g., brand-login, login-brand
    for brand in _get_brands():
        if not brand:
            continue
        brand_l = brand.lower()
        # Skip very short brand names to avoid false positives
        if len(brand_l) < 3:
            continue
            
        # Initialize skeletons for similarity comparison
        brand_skel = skeleton(brand_l)
        main_skel = skeleton(main_label) if main_label else ""
            
        # check if brand appears as a standalone label or prefix/suffix in main_label
        if brand_l == main_label:
            return True, f"domain '{domain}' uses brand label (possible legit or phishing)", brand
            
        # Check for brand in hyphenated parts
        if "-" in main_label:
            parts = main_label.split("-")
            if parts[0] == brand_l or parts[-1] == brand_l:
                return True, f"domain '{domain}' contains brand with modifier (possible impersonation)", brand
                
        # Check for brand as substring with length check
        if brand_l in domain.lower() and len(brand_l) >= 3:
            # Skip if the match is too short or too common
            if len(brand_l) < 3 or brand_l in ['com', 'net', 'org', 'io', 'co']:
                continue
            return True, "domain contains potential brand reference (possible impersonation)", brand
        # Only check similarity if the lengths are somewhat close
        if abs(len(brand_skel) - len(main_skel)) <= 3:  # Allow small differences in length
            if similarity(main_skel, brand_skel) >= HOMOGRAPH_SIMILARITY_THRESHOLD:
                return True, "domain visually similar to known brand", brand
                
        # Check sublabels with similar logic
        for s in sublabels:
            s_skel = skeleton(s)
            if abs(len(brand_skel) - len(s_skel)) <= 3:
                if similarity(s_skel, brand_skel) >= HOMOGRAPH_SIMILARITY_THRESHOLD:
                    return True, "subdomain visually similar to known brand", brand

    # 5. Subdomain impersonation: e.g., shopee.example.com (brand used as subdomain not registered)
    # If brand appears as subdomain while registered domain is different -> suspicious
    for brand in _known_brands_cache:
        if not brand or len(brand) < 3:
            continue
        bl = brand.lower()
        # check subdomain labels explicitly
        for s in sublabels:
            if bl in s.lower():
                return True, f"subdomain '{s}' contains brand '{brand}' while registered domain is '{registered}' (possible impersonation)", brand

    return False, "", None


# Main heuristic scorer
def score_heuristics(body: str, headers: dict, model_only: bool = False) -> Tuple[float, str, List[Dict]]:
    """
    Returns (score_adjustment, explanation, risk_links)
    If STRICT_MODEL_ONLY env or model_only flag is set, heuristics are skipped.
    
    Args:
        body: Email body text
        headers: Dictionary containing email headers
        model_only: If True, skip heuristics and return neutral score
        
    Returns:
        Tuple of (score_adjustment, explanation, risk_links)
    """
    if STRICT_MODEL_ONLY_ENV or model_only:
        return 0.0, "Heuristics skipped (model-only mode)", []
        
    score = 0.0
    explanations = []
    risk_links = []
    
    try:
        # Check for suspicious patterns in body
        suspicious_phrases = [
            "urgent action required", "verify your account", "password expired",
            "suspicious activity", "click here", "login to verify", "unusual login attempt",
            "account suspended", "security alert", "verify your identity"
        ]
        
        body_lower = body.lower()
        for phrase in suspicious_phrases:
            if phrase in body_lower:
                score += 0.1
                explanations.append(f"Suspicious phrase found: '{phrase}'")
        
        # Analyze ALL URLs and include a status entry for each
        urls = headers.get("URLs", [])
        sender_host = extract_domain_host(headers.get("From", ""))
        for url in urls:
            try:
                entry: Dict[str, Any] = {"url": url, "domain": "", "result": "safe", "reasons": []}
                risk_bump = 0.0

                domain = extract_domain_host(url)
                entry["domain"] = domain

                # URL shorteners
                shorteners = {"bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co"}
                if any(s in (url or "").lower() for s in shorteners):
                    risk_bump += 0.2
                    entry["reasons"].append("URL shortener detected")

                # Sender-domain mismatch with homograph/brand-like signal
                if domain:
                    if sender_host and domain != sender_host:
                        try:
                            is_hg, note, _ = check_idn_homograph(domain)
                            if is_hg:
                                risk_bump += 0.3
                                entry["reasons"].append(f"Suspicious domain: {note}")
                        except Exception:
                            pass

                # Map risk_bump to a simple result label
                if risk_bump >= 0.5:
                    entry["result"] = "malicious"
                elif risk_bump > 0.0:
                    entry["result"] = "suspicious"
                else:
                    entry["result"] = "safe"

                # Apply to overall heuristic score
                score += risk_bump

                risk_links.append(entry)
            except Exception as e:
                logger.warning(f"Error checking URL {url}: {e}")
        
        # Cap score between 0 and 1
        score = max(0.0, min(1.0, score))
        
        return score, ". ".join(explanations) if explanations else "No suspicious patterns detected", risk_links
        
    except Exception as e:
        logger.error(f"Error in score_heuristics: {e}", exc_info=True)
        return 0.0, f"Error in heuristics: {str(e)}", []


def analyze_email_links_and_content(msg_id: Optional[str], subject: str, body: str, html_body: str, sender: str):
    """
    Extract links from body/html and run heuristics to produce label/score/risk_links.
    New signature includes msg_id so we can look up attachments from cache for the
    "empty message" short-circuit rule.

    Behavior:
      - If subject and both bodies are empty -> short-circuit and return safe label
        with explanation EXACTLY: "NO TEXT DETECTED"
        If attachments exist in the cached email, append:
        ". THIS MAIL HAVE FILES ATTACHMENT(S). PROCESS WITH CAUTION"

      - Otherwise, perform URL extraction, run score_heuristics, and return structured results.
    """
    urls: List[str] = []

    # quick normalized inputs
    subj = (subject or "").strip()
    body_text = (body or "").strip()
    

    if html_body:
        try:
            html_visible_text, _ = clean_html_for_text(html_body)
            html_text = (html_visible_text or "").strip()
        except Exception:
            html_text = (html_body or "").strip()
    else:
        html_text = ""


    # Helper: consider common placeholders / fallbacks as empty
    def _looks_empty(t: str) -> bool:
        if not t:
            return True
        # ignore short placeholders commonly produced by HTML->text processing
        # such as "(No visible text; possible image-only email)", "(No content)", etc.
        norm = t.strip().lower()
        if norm == "(no content)":
            return True
        if "NO VISIBLE TEXT" in norm:
            return True
        if "NO TEXT DETECTED" in norm:
            return True
        if "FILE ATTACHMENT DETECTED" in norm:
            return True
        # also ignore common one-word placeholders
        if norm in ("", "none"):
            return True
        return False

    # Early short-circuit: no subject and no visible body (treat placeholders as empty)
    if not subj and _looks_empty(body_text) and _looks_empty(html_text):
        # Check for attachments in the email cache
        has_attachments = False
        attachments = []
        
        if msg_id:
            try:
                email_data = email_cache.get_cached_email(msg_id)
                if email_data and 'attachments' in email_data:
                    has_attachments = bool(email_data['attachments'])
                    attachments = email_data['attachments']
            except Exception as e:
                logging.warning(f"Error checking for attachments: {e}")
        
        # Analyze attachments if any
        attachment_analysis = analyze_attachments(attachments)
        
        if has_attachments:
            if attachment_analysis['has_malicious']:
                return {
                    'label': 'phishing',
                    'score': 1.0,
                    'explanation': 'NO TEXT DETECTED. MALICIOUS ATTACHMENT(S) FOUND.',
                    'risk_links': [],
                    'attachments': attachment_analysis
                }
            elif attachment_analysis['has_suspicious']:
                return {
                    'label': 'suspicious',
                    'score': 0.7,
                    'explanation': 'NO TEXT DETECTED. SUSPICIOUS ATTACHMENT(S) FOUND.',
                    'risk_links': [],
                    'attachments': attachment_analysis
                }
            else:
                return {
                    'label': 'safe',
                    'score': 0.0,
                    'explanation': 'NO TEXT DETECTED. ATTACHMENTS APPEAR SAFE.',
                    'risk_links': [],
                    'attachments': attachment_analysis
                }
        else:
            return {
                'label': 'safe',
                'score': 0.0,
                'explanation': 'NO TEXT DETECTED',
                'risk_links': [],
                'attachments': None
            }

    # Extract URLs using robust pattern (handles hxxp variants)
    def find_urls(text):
        if not text:
            return []
        # capture http(s) links and plain domains (basic)
        pattern = r"(https?://[^\s<>\"]+|hxxp://[^\s<>\"]+|[A-Za-z0-9\-\._]+\.[A-Za-z]{2,6}/[^\s<>]*)"
        found = re.findall(pattern, text, flags=re.IGNORECASE)
        clean = []
        for u in found:
            u = u.replace("hxxp://", "http://").strip("()[]<>\"'")
            # ensure we return a usable URL (if it lacks scheme, it's okay; extract_domain_host can handle)
            clean.append(u)
        # dedupe preserving order
        seen = set()
        out = []
        for v in clean:
            if v not in seen:
                seen.add(v)
                out.append(v)
        return out

    urls.extend(find_urls(body_text))
    urls.extend(find_urls(html_text))
    # dedupe again
    seen = set()
    deduped = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    urls = deduped

    headers = {
        "URLs": urls,
        "From": sender,
        # SPF/DKIM/DMARC will be inserted in background_sync via update
        "SPF": "",
        "DKIM": "",
        "DMARC": ""
    }

    # run heuristics using existing scorer
    try:
        heur_adj, heur_exp, risk_links = score_heuristics(body_text, headers, model_only=False)
    except Exception as e:
        logger.exception("[ANALYZE] score_heuristics error: %s", e)
        heur_adj, heur_exp, risk_links = 0.0, "", []

    # convert aggregated heuristics to final label/score mapping (align with existing)
    score_val = heur_adj
    if score_val >= 0.7:
        label = "phish"
    elif score_val >= 0.4:
        label = "maybephish"
    else:
        label = "safe"

    explanation = heur_exp or ""
    return {
        "label": label,
        "score": float(score_val),
        "explanation": explanation,
        "urls": urls,
        "risk_links": risk_links
    }


# expose for import
__all__ = [
    "score_heuristics",
    "analyze_email_links_and_content",
    "check_idn_homograph",
    "is_reachable",
    "extract_domain_host",
    "get_known_brands",
    "_get_whitelist_emails"
]
