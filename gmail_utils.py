import base64
import logging
import re
import time
import random
import threading
import os
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup  # type: ignore[import-not-found]
from urllib.parse import urlparse, unquote
from googleapiclient.errors import HttpError  # type: ignore[import-not-found]
from concurrent.futures import ThreadPoolExecutor, as_completed

# Try to import auth_handler, but don't fail if it's not available
try:
    from auth_handler import get_gmail_service
except ImportError:
    get_gmail_service = None

# ============================================================== 
# Logger Setup
# ==============================================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gmail_utils")

# ============================================================== 
# Rate limiting + backoff helpers (lightweight, process-local)
# ==============================================================

_rate_state = {}  # { key: { "tokens": int, "last": float, "period": float, "capacity": int } }
_rate_lock = threading.Lock()

def init_rate_bucket(key, capacity, period_seconds):
    with _rate_lock:
        if key not in _rate_state:
            _rate_state[key] = {"tokens": capacity, "last": time.time(), "period": period_seconds, "capacity": capacity}

def _consume_token(key, tokens=1):
    now = time.time()
    with _rate_lock:
        s = _rate_state.get(key)
        if s is None:
            return False
        # refill tokens proportional to elapsed time relative to period
        elapsed = now - s["last"]
        if s["period"] > 0:
            refill_units = int(elapsed / s["period"])
            if refill_units > 0:
                s["tokens"] = min(s["capacity"], s["tokens"] + refill_units)
                s["last"] = now
        if s["tokens"] >= tokens:
            s["tokens"] -= tokens
            return True
        return False

def backoff_with_jitter(attempt):
    base = min(2 ** attempt, 60)
    return base * (0.5 + random.random() * 0.5)

# Initialize a conservative Gmail bucket (adjust if you know your quota)
init_rate_bucket("gmail", 60, 60)  # 60 tokens / 60 seconds

# ============================================================== 
# URL Matching Patterns
# ==============================================================

URL_FIND_RE = re.compile(
    r"(?:(?:https?|ftp):\/\/|www\.)[^\s'\"<>()]+", re.IGNORECASE
)

# ============================================================== 
# Gmail API Service Initialization
# ==============================================================

def get_service(user_email=None):
    """
    Safely return a Gmail API service instance using OAuth2.
    First tries to use the logged-in user's authentication token,
    falls back to the legacy token.json method.

    Args:
        user_email: Optional user email to use for token lookup.
                   If None, tries to get from Flask session, or finds available user token.
    """
    try:
        # First try to use the logged-in user's token
        if user_email is None:
            try:
                from flask import session, g
                user_email = session.get('user_email')
            except RuntimeError as e:
                # Handle "Working outside of request context" error
                if "request context" in str(e):
                    logger.debug("[GMAIL] No Flask request context, looking for available user tokens")
                    # Find an available user token with Gmail scope
                    user_token_dir = os.path.join(os.path.dirname(__file__), "cache", "user_tokens")
                    if os.path.exists(user_token_dir):
                        for filename in os.listdir(user_token_dir):
                            if filename.endswith('.json'):
                                token_path = os.path.join(user_token_dir, filename)
                                try:
                                    import json
                                    with open(token_path, 'r') as f:
                                        token_data = json.load(f)
                                        scopes = token_data.get('scopes', [])
                                        if "https://www.googleapis.com/auth/gmail.readonly" in scopes:
                                            user_email = filename.replace('.json', '')
                                            logger.info(f"[GMAIL] Found user token for {user_email} with Gmail scope")
                                            break
                                except Exception:
                                    continue
                    if user_email is None:
                        logger.warning("[GMAIL] No Flask request context and no user tokens with Gmail scope found")
                else:
                    raise

        if user_email:
            # Try to load user's auth token
            user_token_dir = os.path.join(os.path.dirname(__file__), "cache", "user_tokens")
            user_token_file = os.path.join(user_token_dir, f"{user_email}.json")

            if os.path.exists(user_token_file):
                try:
                    import json
                    from google.oauth2.credentials import Credentials  # type: ignore[import-not-found]
                    from googleapiclient.discovery import build  # type: ignore[import-not-found]

                    with open(user_token_file, 'r') as f:
                        token_data = json.load(f)

                    creds = Credentials(
                        token=token_data.get('token'),
                        refresh_token=token_data.get('refresh_token'),
                        token_uri=token_data.get('token_uri'),
                        client_id=token_data.get('client_id'),
                        client_secret=token_data.get('client_secret'),
                        scopes=token_data.get('scopes', [])
                    )

                    # Check if token is valid and refresh if needed
                    from google.auth.transport.requests import Request  # type: ignore[import-not-found]
                    if creds.expired and creds.refresh_token:
                        creds.refresh(Request())

                    # Verify Gmail scope is present
                    if "https://www.googleapis.com/auth/gmail.readonly" in creds.scopes:
                        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
                        logger.info(f"[GMAIL] Gmail service created using user token for {user_email}")
                        return service
                    else:
                        logger.warning(f"[GMAIL] User token for {user_email} lacks Gmail scope")

                except Exception as e:
                    logger.warning(f"[GMAIL] Failed to use user token for {user_email}: {e}")

        # Fall back to legacy method
        if not get_gmail_service:
            logger.error("[GMAIL] Gmail service not available - auth_handler module not found")
            return None

        service = get_gmail_service()
        if not service:
            raise Exception("Failed to create Gmail service.")
        logger.info("[GMAIL] Gmail service created using legacy token.json method")
        return service

    except Exception as e:
        logger.error(f"[GMAIL] Error initializing Gmail service: {e}")
        return None


# ============================================================== 
# URL Normalization Utilities
# ==============================================================

def _shorten_url_for_model(url: str, keep_path_chars: int = 20) -> str:
    """
    Shorten URLs for text summarization or phishing model readability.
    Keeps only a portion of the path while preserving the domain.
    """
    try:
        if url.startswith("www."):
            url = "https://" + url
        p = urlparse(url)
        domain = p.hostname or url
        path = p.path or ""
        path = unquote(path)
        last = path.rstrip("/").split("/")[-1] if path else ""
        if last and len(last) > keep_path_chars:
            last = last[:keep_path_chars] + "..."
        if last:
            return f"{domain}/{last}"
        return domain
    except Exception:
        return url[:60]


# ============================================================== 
# URL Extraction from Plain Text and HTML
# ==============================================================

def extract_links_from_text(text: str):
    """
    Extract URLs from plain text, normalize, and deduplicate.
    This function also repairs obfuscated phishing-style URLs like hxxp://.
    """
    if not text:
        return []

    raw_urls = re.findall(
        r"(https?://[^\s'\"<>]+|hxxps?://[^\s'\"<>]+|hxxp://[^\s'\"<>]+|www\.[^\s'\"<>]+)",
        text
    )

    cleaned_urls = []
    for u in raw_urls:
        if not u:
            continue

        url = u.strip()
        url = url.replace("hxxp://", "http://").replace("hxxps://", "https://")
        url = url.replace("[.]", ".").replace("(.)", ".")

        try:
            url = unquote(url)
        except Exception:
            pass

        if "google.com/url?q=" in url:
            m = re.search(r"google\.com/url\?q=([^&]+)", url)
            if m:
                url = unquote(m.group(1))
        elif "urldefense.com" in url and "__" in url:
            m = re.search(r"__https?:(.*?)__", url)
            if m:
                url = "https:" + m.group(1)

        if url.startswith("www."):
            url = "https://" + url

        if not url.lower().startswith(("http://", "https://")):
            continue

        try:
            parsed = urlparse(url)
            url = parsed._replace(netloc=parsed.netloc.lower(), fragment="").geturl()
        except Exception:
            pass

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


def extract_links_from_html(soup: BeautifulSoup):
    """
    Extract URLs from HTML soup tags and inner text.
    Returns deduplicated and normalized URLs.
    """
    urls = set()

    for tag in soup.find_all(href=True):
        urls.add(tag["href"])
    for tag in soup.find_all(src=True):
        urls.add(tag["src"])
    for tag in soup.find_all(action=True):
        urls.add(tag["action"])

    # Also find URLs hidden inside text nodes
    text = soup.get_text(" ", strip=True)
    text_urls = re.findall(
        r"(https?://[^\s'\"<>]+|hxxps?://[^\s'\"<>]+|www\.[^\s'\"<>]+)",
        text
    )
    urls.update(text_urls)

    cleaned_urls = set()
    for url in urls:
        if not url:
            continue
        u = url.strip().replace("hxxp://", "http://").replace("hxxps://", "https://")
        u = u.replace("[.]", ".").replace("(.)", ".")
        try:
            u = unquote(u)
        except Exception:
            pass

        if "google.com/url?q=" in u:
            match = re.search(r"google\.com/url\?q=([^&]+)", u)
            if match:
                u = unquote(match.group(1))
        elif "urldefense.com" in u and "__" in u:
            match = re.search(r"__https?:(.*?)__", u)
            if match:
                u = "https:" + match.group(1)

        if not u.lower().startswith(("http://", "https://", "www.")):
            continue

        try:
            parsed = urlparse(u)
            normalized = parsed._replace(netloc=parsed.netloc.lower(), fragment="").geturl()
        except Exception:
            normalized = u

        cleaned_urls.add(normalized)

    final_urls = list(dict.fromkeys(sorted(cleaned_urls)))
    return final_urls


# ============================================================== 
# HTML Cleaning and Text Conversion
# ==============================================================
 
def clean_html_for_text(html_content: str):
    """
    Sanitize HTML to plain text suitable for phishing models.
    Replaces scripts, inline elements, and embedded links with readable text.
    """
    soup = BeautifulSoup(html_content or "", "html.parser")

    for tag in soup(["script", "style", "meta", "link", "head", "title", "noscript"]):
        tag.decompose()

    for img in soup.find_all("img"):
        alt = img.get("alt")
        if alt:
            img.replace_with(f"[Image: {alt}]")
        else:
            img.decompose()

    urls = extract_links_from_html(soup)
    urls = list(dict.fromkeys(urls))

    for a in soup.find_all("a"):
        href = a.get("href", "")
        text = a.get_text(strip=True)
        if href:
            short = _shorten_url_for_model(href)
            a.replace_with(f"{text or '[Link]'} [URL: {short}]")

    text = soup.get_text(separator=" ", strip=True)
    text = re.sub(r"\s+", " ", text).strip()

    if not text:
        text = "(NO TEXT DETECTED)"

    return text, urls


# ============================================================== 
# MIME Body Parsing
# ==============================================================

def extract_bodies_from_mime(raw_bytes):
    """
    Extract both text and HTML bodies from MIME emails.
    Handles embedded images, multipart messages, and attachments.
    """
    text_body = ""
    html_body = ""
    cid_map = {}

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

        def walk_parts(part):
            nonlocal text_body, html_body
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", "")).lower()
            cid = part.get("Content-ID", "").strip("<>")
            if part.is_multipart():
                for subpart in part.iter_parts():
                    walk_parts(subpart)
            else:
                payload = part.get_payload(decode=True)
                if not payload:
                    return

                charset = part.get_content_charset() or "utf-8"
                try:
                    content = payload.decode(charset, errors="replace")
                except Exception:
                    content = payload.decode("utf-8", errors="replace")

                if ctype == "text/plain" and "attachment" not in disp:
                    text_body += "\n" + content
                elif ctype == "text/html" and "attachment" not in disp:
                    html_body += "\n" + content
                elif cid:
                    b64 = base64.b64encode(payload).decode("utf-8")
                    cid_map[cid] = f"data:{ctype};base64,{b64}"

        walk_parts(msg)

    except Exception as e:
        logger.error(f"[GMAIL] MIME parse error: {e}")

    if html_body and cid_map:
        for cid, data_uri in cid_map.items():
            html_body = html_body.replace(f"cid:{cid}", data_uri)

    return text_body.strip(), html_body.strip()


# ============================================================== 
# Base64 Helpers
# ==============================================================

def decode_base64_data(data: str) -> bytes:
    """
    Decode Gmail’s URL-safe base64 encoding.
    Returns empty bytes on error to avoid pipeline crashes.
    """
    if not data:
        return b""
    try:
        return base64.urlsafe_b64decode(data.encode("utf-8"))
    except Exception as e:
        logger.error(f"[GMAIL] Base64 decode error: {e}")
        try:
            return base64.b64decode(data.encode("utf-8"))
        except Exception:
            return b""


# ============================================================== 
# Fetch All Gmail Messages (Parallel)
# ==============================================================

def fetch_all_messages(max_results=-1, user_email=None):
    """
    Retrieve all Gmail messages with bodies, URLs, and cleaned text.
    Used by phishing analysis modules and caching system.

    Args:
        max_results: Maximum number of messages to fetch (-1 for all)
        user_email: Optional user email to use for token lookup
    """
    service = get_service(user_email)
    if not service:
        logger.error("[GMAIL] Gmail service unavailable.")
        return []

    results = []
    try:
        total_fetched = 0
        page_token = None
        per_page = 500 if max_results <= 0 else min(max_results, 500)

        logger.info(f"[GMAIL] Fetching message IDs (max_results={max_results})...")

        while True:
            # Client-side rate limiting before hitting API
            # If token unavailable, sleep briefly and retry
            wait_attempts = 0
            while not _consume_token("gmail"):
                wait_attempts += 1
                time.sleep(min(1 + wait_attempts * 0.2, 5))

            try:
                response = service.users().messages().list(
                    userId="me", includeSpamTrash=True, maxResults=per_page, pageToken=page_token
                ).execute()
            except HttpError as e:
                status = None
                try:
                    status = e.resp.status
                except Exception:
                    pass

                # Try to read Retry-After header
                retry_after = None
                try:
                    retry_after = int(e.resp.get("retry-after")) if hasattr(e, "resp") and e.resp.get("retry-after") else None
                except Exception:
                    retry_after = None

                if status == 429 or "rateLimitExceeded" in str(e):
                    wait = retry_after if retry_after and retry_after > 0 else backoff_with_jitter(0)
                    logger.warning(f"[GMAIL] rate limited; sleeping {wait}s before retrying list: {e}")
                    time.sleep(wait)
                    continue
                logger.error(f"[GMAIL] API error while listing messages: {e}")
                break

            messages = response.get("messages", [])
            if not messages:
                break

            results.extend(messages)
            total_fetched += len(messages)
            logger.info(f"[GMAIL] Got {len(messages)} message IDs (total {total_fetched})")

            page_token = response.get("nextPageToken")
            if not page_token or (max_results > 0 and total_fetched >= max_results):
                break

        if not results:
            logger.warning("[GMAIL] No messages found.")
            return []

        logger.info(f"[GMAIL] Collected {len(results)} message IDs. Starting parallel fetch...")

        def process_message(meta):
            msg_id = meta["id"]
            try:
                local_service = get_service(user_email)
                if not local_service:
                    logger.error(f"[GMAIL] No service available for message {msg_id}")
                    return None

                full_msg = None
                # protect from hammering
                for attempt in range(4):
                    try:
                        # rate-limit per message get
                        while not _consume_token("gmail"):
                            time.sleep(0.2)
                        full_msg = local_service.users().messages().get(
                            userId="me", id=msg_id, format="raw"
                        ).execute()
                        break
                    except HttpError as e:
                        status = getattr(e.resp, "status", None) if hasattr(e, "resp") else None
                        retry_after = None
                        try:
                            retry_after = int(e.resp.get("retry-after")) if hasattr(e, "resp") and e.resp.get("retry-after") else None
                        except Exception:
                            retry_after = None
                        if status == 429 or "rateLimitExceeded" in str(e):
                            wait = retry_after if retry_after and retry_after > 0 else backoff_with_jitter(attempt)
                            logger.warning(f"[GMAIL] rate limited for message {msg_id}; sleeping {wait}s (attempt {attempt+1})")
                            time.sleep(wait)
                            continue
                        if attempt == 3:
                            raise
                        time.sleep(backoff_with_jitter(attempt))

                # Check if we got the message
                if not full_msg:
                    logger.error(f"[GMAIL] Failed to fetch message after retries: {msg_id}")
                    return None

                raw_data = full_msg.get("raw", "")
                internal_date = int(full_msg.get("internalDate", 0))
                raw_bytes = base64.urlsafe_b64decode(raw_data.encode("utf-8"))

                mime = BytesParser(policy=policy.default).parsebytes(raw_bytes)
                subject = mime.get("subject", "")
                sender = mime.get("from", "")
                date = mime.get("date", "")
                snippet = full_msg.get("snippet", "")

                text_body, html_body = extract_bodies_from_mime(raw_bytes)

                # --- Attachment extraction ---
                attachments = []
                try:
                    meta_msg = local_service.users().messages().get(
                        userId="me", id=msg_id, format="full"
                    ).execute()
                    attachments = extract_attachments(local_service, "me", meta_msg)
                except Exception as e:
                    logger.warning(f"[GMAIL] Failed to extract attachments for {msg_id}: {e}")
                    attachments = []

                if html_body:
                    cleaned_text, urls = clean_html_for_text(html_body)
                elif text_body:
                    cleaned_text, urls = clean_html_for_text(text_body)
                else:
                    # fallback: snippet may be None
                    fallback = snippet if snippet else ""
                    cleaned_text, urls = fallback, []


                # --- Final empty-text logic based on attachments ---
                if cleaned_text.strip() in ("", "(NO TEXT DETECTED)"):
                    if attachments:
                        cleaned_text = "NO TEXT DETECTED; possibly an empty email with attachment(s)"
                    else:
                        cleaned_text = "NO TEXT DETECTED; possibly an empty email"

                combined_text = f"{subject}. {cleaned_text}".strip()

                return {
                    "id": msg_id,
                    "msg_id": msg_id,
                    "subject": subject,
                    "sender": sender,
                    "date": date,
                    "internal_date": internal_date,
                    "snippet": snippet,
                    "body": combined_text,
                    "html_body": html_body,
                    "raw": raw_data,
                    "urls": urls,
                    "attachments": attachments,  # added for caching
                }

            except Exception as e:
                logger.error(f"[GMAIL] Error parsing message {msg_id}: {e}")
                logger.debug(f"[GMAIL] Full traceback for {msg_id}:", exc_info=True)
                return None

        parsed_results = []
        failed_count = 0
        max_workers = 5

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(process_message, m) for m in results]
            for i, fut in enumerate(as_completed(futures), 1):
                try:
                    msg = fut.result(timeout=60)  # Increased timeout to 60 seconds for large emails
                    if msg:
                        parsed_results.append(msg)
                    else:
                        failed_count += 1
                except Exception as e:
                    failed_count += 1
                    logger.warning(f"[GMAIL] Failed to process message {i}: {e}")

                if i % 10 == 0:
                    logger.info(f"[GMAIL] Processed {i}/{len(futures)} messages ({len(parsed_results)} successful, {failed_count} failed)...")

        logger.info(f"[GMAIL] Finished fetching {len(parsed_results)} messages total ({failed_count} failed).")
        return parsed_results

    except Exception as e:
        logger.error(f"[GMAIL] Unexpected fetch error: {e}")
        return []


# ============================================================== 
# HTML Extraction for Renderer
# ==============================================================

def extract_html_from_email(raw_bytes: bytes) -> str:
    """
    Return the HTML body (or fallback text) for rendering inside message iframe.
    """
    try:
        text_body, html_body = extract_bodies_from_mime(raw_bytes)
        if html_body:
            return html_body.strip()
        if text_body:
            safe = text_body.replace("<", "&lt;").replace(">", "&gt;")
            return f"<pre>{safe}</pre>"
        return "<p>(No content)</p>"
    except Exception as e:
        logger.error(f"[GMAIL] extract_html_from_email error: {e}")
        return "<p>Error reading email body</p>"


# ============================================================== 
# Attachment Extraction and Download
# ==============================================================

def extract_attachments(service, user_id, message):
    """
    Extract metadata for all attachments in a Gmail message.
    Each attachment is returned as:
    {
        'filename': str,
        'mimeType': str,
        'size': int,
        'attachmentId': str
    }
    """
    attachments = []
    try:
        payload = message.get("payload", {})
        parts = payload.get("parts", [])
        for part in parts:
            if part.get("filename"):
                body = part.get("body", {})
                att_id = body.get("attachmentId")
                if att_id:
                    attachments.append({
                        "filename": part["filename"],
                        "mimeType": part.get("mimeType"),
                        "size": body.get("size", 0),
                        "attachmentId": att_id
                    })
        return attachments
    except Exception as e:
        logger.error(f"[GMAIL] Error extracting attachments: {e}")
        return []


def get_attachment_data(service, user_id, msg_id, att_id):
    """
    Download attachment binary content from Gmail.
    Returns decoded bytes or None on failure.
    """
    try:
        # respect client-side rate limit
        for attempt in range(4):
            if not _consume_token("gmail"):
                time.sleep(0.2)
            try:
                att = service.users().messages().attachments().get(
                    userId=user_id, messageId=msg_id, id=att_id
                ).execute()
                data = att.get("data")
                if not data:
                    return None
                return base64.urlsafe_b64decode(data)
            except HttpError as e:
                status = None
                try:
                    status = e.resp.status
                except Exception:
                    status = None
                retry_after = None
                try:
                    retry_after = int(e.resp.get("retry-after")) if hasattr(e, "resp") and e.resp.get("retry-after") else None
                except Exception:
                    retry_after = None
                if status == 429 or "rateLimitExceeded" in str(e):
                    wait = retry_after if retry_after and retry_after > 0 else backoff_with_jitter(attempt)
                    logger.warning(f"[GMAIL] rate limited fetching attachment {att_id}; sleeping {wait}s (attempt {attempt+1})")
                    time.sleep(wait)
                    continue
                if attempt == 3:
                    raise
                time.sleep(backoff_with_jitter(attempt))
        return None
    except HttpError as e:
        logger.error(f"[GMAIL] Error fetching attachment {att_id} for {msg_id}: {e}")
        return None
    except Exception as e:
        logger.error(f"[GMAIL] Unexpected attachment error: {e}")
        return None
