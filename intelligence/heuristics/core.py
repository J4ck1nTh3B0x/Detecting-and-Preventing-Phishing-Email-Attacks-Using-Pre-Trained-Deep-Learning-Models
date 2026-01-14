"""
Core heuristics analysis for phishing detection.
"""
import re
import logging
import os
from typing import Dict, List, Tuple, Optional, Any, Set
import requests

from .config import HOMOGRAPH_SIMILARITY_THRESHOLD, REQUEST_TIMEOUT, STRICT_MODEL_ONLY_ENV
from .domain_utils import extract_domain_host, is_reachable, extract_domain_from_email
from .homograph import check_idn_homograph
from .brand_analysis import is_brand_domain, resolve_brand

logger = logging.getLogger("heuristics.core")

def score_heuristics(body: str, headers: dict, model_only: bool = False) -> Tuple[float, str, List[Dict]]:
    """
    Main heuristic scoring function.
    
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
        # Extract URLs from body and merge with any URLs provided in headers
        urls = _extract_urls(body)
        try:
            header_urls = headers.get("URLs", []) if isinstance(headers, dict) else []
        except Exception:
            header_urls = []
        # dedupe while preserving order
        merged = []
        seen: Set[str] = set()
        for u in (urls or []):
            if u and u not in seen:
                merged.append(u)
                seen.add(u)
        for u in (header_urls or []):
            if u and u not in seen:
                merged.append(u)
                seen.add(u)
        urls = merged
        
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
        
        # Analyze URLs
        sender_domain = extract_domain_from_email(headers.get("From", ""))
        for url in urls:
            try:
                url_risk = _analyze_url(url, sender_domain)
                if url_risk:
                    risk_links.append(url_risk)
                    score += url_risk.get("risk_score", 0.1)
            except Exception as e:
                logger.warning(f"Error analyzing URL {url}: {e}")
        
        # Check for sender-recipient domain mismatch
        if "To" in headers and "From" in headers:
            to_domain = extract_domain_from_email(headers["To"])
            from_domain = extract_domain_from_email(headers["From"])
            if to_domain and from_domain and to_domain != from_domain:
                explanations.append(f"Sender domain '{from_domain}' differs from recipient domain '{to_domain}'")
        
        # Cap score between 0 and 1
        score = max(0.0, min(1.0, score))
        
        return score, ". ".join(explanations) if explanations else "No suspicious patterns detected", risk_links
        
    except Exception as e:
        logger.error(f"Error in score_heuristics: {e}", exc_info=True)
        return 0.0, f"Error in heuristics: {str(e)}", []

def _extract_urls(text: str) -> List[str]:
    """Extract URLs from text."""
    if not text:
        return []
    
    # Simple URL regex (covers most common cases)
    url_pattern = r'https?://[^\s<>"\[\]\\]+|www\.[^\s<>"\[\]\\]+'
    urls = re.findall(url_pattern, text, re.IGNORECASE)
    
    # Clean up and deduplicate
    cleaned = []
    seen = set()
    for url in urls:
        url = url.strip("'\"()[]{}<>")
        if url and url not in seen:
            seen.add(url)
            cleaned.append(url)
    
    return cleaned

def _analyze_url(url: str, sender_domain: str) -> Optional[Dict]:
    """Analyze a single URL for potential risks."""
    if not url:
        return None
    
    result = {"url": url, "risk_score": 0.0, "reasons": []}
    
    try:
        # Check for URL shorteners
        shorteners = {"bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "rb.gy"}
        if any(shortener in url.lower() for shortener in shorteners):
            result["risk_score"] += 0.3
            result["reasons"].append("URL shortener detected")
        
        # Extract domain
        domain = extract_domain_host(url)
        if not domain:
            return None
            
        # Check if domain is brand impersonation
        is_homograph, note, brand = check_idn_homograph(domain)
        if is_homograph and brand:
            result["risk_score"] += 0.5
            result["reasons"].append(f"Possible brand impersonation: {note}")
        
        # Check if domain is known brand
        if is_brand_domain(domain):
            result["risk_score"] -= 0.1  # Slight negative adjustment for known brands
        
        # Check if domain matches sender domain
        if sender_domain and domain != sender_domain:
            result["risk_score"] += 0.2
            result["reasons"].append(f"Domain '{domain}' doesn't match sender domain '{sender_domain}'")
        
        # Check if domain is reachable
        if not is_reachable(url):
            result["risk_score"] += 0.2
            result["reasons"].append("URL is not reachable")
        
        # Check for suspicious patterns in URL
        suspicious_patterns = [
            (r"\b(login|signin|verify|account|update|secure|support|security)\b", 0.2),
            (r"\b(paypal|bank|ebay|amazon|microsoft|apple|netflix|dropbox)\b", 0.3),
            (r"\b(\d{1,3}\.){3}\d{1,3}\b", 0.4),  # Raw IP address
        ]
        
        for pattern, risk in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                result["risk_score"] += risk
                result["reasons"].append(f"Suspicious pattern in URL: {pattern}")

        # Google Safe Browsing (hash-only URL reputation) — optional
        try:
            gsb_key = os.getenv("GOOGLE_SAFEBROWSING_API_KEY") or os.getenv("GSB_API_KEY")
            if gsb_key:
                gsb = _gsb_lookup(url, gsb_key)
                if gsb and gsb.get("matches"):
                    # Aggregate threat types
                    types = list({m.get("threatType", "UNKNOWN") for m in gsb.get("matches", [])})
                    result["reasons"].append(f"Google Safe Browsing hit: {', '.join(types)}")
                    # Boost risk meaningfully; cap later
                    result["risk_score"] += 0.6
                    # Provide a simple status for UI consumers if they want it
                    if any(t in ("MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION") for t in types):
                        result["result"] = "malicious"
                    else:
                        result["result"] = "suspicious"
                    result["gsb"] = {"threat_types": types}
        except Exception as _:
            # Network/parse issues are non-fatal
            pass
        
        # URLScan.io public search (optional)
        try:
            us = _urlscan_lookup(url)
            if us and us.get("hits", 0) > 0:
                verdict = us.get("verdict") or "unknown"
                bump = 0.15
                if verdict == "malicious":
                    bump = 0.4
                elif verdict == "suspicious":
                    bump = 0.25
                result["risk_score"] += bump
                result["reasons"].append(f"URLScan.io seen ({verdict})")
                result["urlscan"] = {"verdict": verdict, "hits": us.get("hits", 0)}
        except Exception:
            pass

        # PhishTank check (optional; requires PHISHTANK_APP_KEY)
        try:
            pt_key = os.getenv("PHISHTANK_APP_KEY")
            if pt_key:
                pt = _phishtank_lookup(url, pt_key)
                if pt is True:
                    result["risk_score"] += 0.6
                    result["reasons"].append("PhishTank: verified phishing")
                    result["phishtank"] = {"status": "verified"}
                elif pt is False:
                    result["reasons"].append("PhishTank: not found")
                    result["phishtank"] = {"status": "not_found"}
        except Exception:
            pass
        
        # Cap risk score
        result["risk_score"] = max(0.0, min(1.0, result["risk_score"]))
        
        return result if result["risk_score"] > 0 else None
        
    except Exception as e:
        logger.warning(f"Error analyzing URL {url}: {e}")
        return None

__all__ = [
    'score_heuristics',
    'extract_domain_host',
    'is_brand_domain',
    'resolve_brand'
]

def _gsb_lookup(url: str, api_key: str) -> Optional[Dict[str, Any]]:
    """Query Google Safe Browsing v4 for a single URL. Returns JSON or None."""
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {"clientId": "phishing-email-app", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        r = requests.post(endpoint, json=payload, timeout=float(REQUEST_TIMEOUT))
        if r.status_code == 200:
            data = r.json() or {}
            # API returns {} when no matches
            if data.get("matches"):
                return data
            return {"matches": []}
        return None
    except Exception:
        return None

def _urlscan_lookup(url: str) -> Optional[Dict[str, Any]]:
    try:
        q = f'url:"{url}"'
        r = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": q},
            timeout=float(REQUEST_TIMEOUT),
        )
        if r.status_code != 200:
            return None
        data = r.json() or {}
        results = data.get("results") or []
        hits = int(data.get("total") or len(results) or 0)
        verdict = "unknown"
        for it in results[:3]:
            overall = (it.get("verdicts") or {}).get("overall") or {}
            if overall.get("malicious") is True:
                verdict = "malicious"
                break
            if verdict == "unknown" and overall.get("score", 0) or overall.get("malicious", False):
                verdict = "suspicious"
        return {"hits": hits, "verdict": verdict}
    except Exception:
        return None

def _phishtank_lookup(url: str, app_key: str) -> Optional[bool]:
    try:
        r = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json", "app_key": app_key},
            timeout=float(REQUEST_TIMEOUT),
        )
        if r.status_code != 200:
            return None
        j = r.json() or {}
        data = j.get("results") or {}
        if data.get("in_database") and data.get("verified"):
            return True
        if data.get("in_database") is False:
            return False
        return None
    except Exception:
        return None
