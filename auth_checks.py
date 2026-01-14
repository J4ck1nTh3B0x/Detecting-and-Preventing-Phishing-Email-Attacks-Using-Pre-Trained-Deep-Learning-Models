# auth_checks.py
"""
Parse SPF / DKIM / DMARC results from raw MIME using common headers.

Returns a tuple (spf, dkim, dmarc) each as one of:
pass | fail | none | neutral | temperror | permerror | unknown
"""

import base64
import logging
from email import policy
from email.parser import BytesParser
from typing import Tuple, Optional

logger = logging.getLogger("auth_checks")


def parse_authentication_results(raw_b64: str) -> Tuple[str, str, str]:
    """
    Given a Gmail 'raw' message (URL-safe base64), parse the message and
    extract SPF/DKIM/DMARC results from:
      - Authentication-Results
      - ARC-Authentication-Results
      - Received-SPF (fallback)
      - DKIM-Signature (fallback heuristic: presence != pass, but we try)
    """
    try:
        if not raw_b64:
            return "unknown", "unknown", "unknown"

        raw = _decode_urlsafe_b64(raw_b64)
        if not raw:
            return "unknown", "unknown", "unknown"

        msg = BytesParser(policy=policy.default).parsebytes(raw)

        # Prefer Authentication-Results family
        ar_all = " ".join([
            (msg.get("Authentication-Results", "") or ""),
            (msg.get("ARC-Authentication-Results", "") or ""),
        ])

        spf = _extract_key_result(ar_all, "spf")
        dkim = _extract_key_result(ar_all, "dkim")
        dmarc = _extract_key_result(ar_all, "dmarc")

        # Fallbacks
        if not spf:
            spf = _extract_from_header(msg.get("Received-SPF"))
        if not dkim:
            # DKIM-Signature existing doesn't guarantee PASS; try to see common tokens
            dkim = _infer_dkim_from_signature(msg.get("DKIM-Signature"))

        return (spf or "unknown").lower(), (dkim or "unknown").lower(), (dmarc or "unknown").lower()

    except Exception as e:
        logger.warning(f"[AUTH] parse failed: {e}")
        return "unknown", "unknown", "unknown"


# ---------------------------------------------------------------------------

def _decode_urlsafe_b64(data: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(data.encode("utf-8"))
    except Exception:
        try:
            return base64.b64decode(data.encode("utf-8"))
        except Exception:
            return b""


def _extract_key_result(ar_text: str, key: str) -> Optional[str]:
    """
    Find tokens like 'spf=pass', 'dkim=fail', 'dmarc=none' in Authentication-Results.
    Returns the value or None.
    """
    if not ar_text:
        return None
    key = key.lower()
    # Split on whitespace and semicolons to be tolerant of formatting
    for token in ar_text.lower().replace(";", " ").split():
        if token.startswith(key + "="):
            val = token.split("=", 1)[1].strip(" ;,")
            if val:
                return val
    return None


def _extract_from_header(header_value: Optional[str]) -> Optional[str]:
    """
    Parse generic headers and try to map to pass/fail/none/neutral.
    """
    if not header_value:
        return None
    v = header_value.lower()
    if "pass" in v:
        return "pass"
    if "fail" in v:
        return "fail"
    if "none" in v:
        return "none"
    if "neutral" in v:
        return "neutral"
    if "temperror" in v or "temp error" in v:
        return "temperror"
    if "permerror" in v or "perm error" in v:
        return "permerror"
    return None


def _infer_dkim_from_signature(header_value: Optional[str]) -> Optional[str]:
    """
    Very conservative: if there's a DKIM-Signature, but no Authentication-Results,
    we cannot assert PASS. Some MTAs add 'b=' and 'd=' yet signature may be invalid.
    We return 'unknown' unless a 'dkim=pass/fail' was seen elsewhere.
    """
    if not header_value:
        return None
    v = header_value.lower()
    # Some providers append result hints near DKIM-Signature in transit (rare).
    # Try to detect them; otherwise return None so caller will use 'unknown'.
    if "dkim=pass" in v:
        return "pass"
    if "dkim=fail" in v:
        return "fail"
    return None

# ---------------------------------------------------------------------------
# Compatibility wrapper for background_sync.py
# ---------------------------------------------------------------------------

def verify_message_auth(raw_email: str, sender: str):
    """
    Wrapper for SOC pipeline. Reuses parse_authentication_results() to extract
    SPF, DKIM, and DMARC from Gmail raw content.
    """
    try:
        spf, dkim, dmarc = parse_authentication_results(raw_email)
    except Exception:
        return "unknown", "unknown", "unknown"
    return spf, dkim, dmarc
