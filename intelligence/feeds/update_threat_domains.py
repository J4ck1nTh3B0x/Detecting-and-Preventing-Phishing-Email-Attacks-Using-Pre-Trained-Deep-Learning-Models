"""
update_threat_domains.py

Collect threat feeds (openphish, phishtank). Feed URLs and timeouts are
configurable via environment variables. Writes to ../cache/threat.json.
"""

import os
import json
import re
import time
import logging
import datetime
from pathlib import Path
from urllib.parse import urlparse
import requests

LOG = logging.getLogger("update_threat_domains")
LOG.setLevel(os.getenv("LOG_LEVEL", "INFO"))

# Paths
BASE_DIR = Path(__file__).resolve().parent
CACHE_DIR = (BASE_DIR / ".." / "cache").resolve()
THREAT_FILE = CACHE_DIR / "threat.json"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Config (no hard-coded values)
OPENPHISH_FEED = os.getenv("OPENPHISH_FEED", "https://openphish.com/feed.txt")
PHISHTANK_FEED = os.getenv("PHISHTANK_FEED", "https://data.phishtank.com/data/online-valid.csv")
FETCH_TIMEOUT = float(os.getenv("THREAT_FETCH_TIMEOUT", "30"))
FETCH_RETRIES = int(os.getenv("THREAT_FETCH_RETRIES", "3"))
RATE_CAPACITY = int(os.getenv("THREAT_RATE_CAPACITY", "10"))
RATE_PERIOD = float(os.getenv("THREAT_RATE_PERIOD", "60"))

# simple token bucket
_rate_state = {}
import threading
_rate_lock = threading.Lock()

def init_rate_bucket(key, capacity, period):
    with _rate_lock:
        if key not in _rate_state:
            _rate_state[key] = {"tokens": capacity, "last": time.time(), "period": period, "capacity": capacity}

def _consume_token(key, tokens=1):
    now = time.time()
    with _rate_lock:
        s = _rate_state.get(key)
        if not s:
            return False
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

def backoff(attempt: int) -> float:
    base = min(2 ** attempt, 60)
    return base * (0.5 + (os.urandom(1)[0] / 255.0) * 0.5)

init_rate_bucket("threat_fetch", RATE_CAPACITY, RATE_PERIOD)

def _fetch_with_retries(url: str, timeout: float, attempts: int):
    for attempt in range(attempts):
        if not _consume_token("threat_fetch"):
            time.sleep(0.2)
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code == 429:
                ra = r.headers.get("Retry-After")
                try:
                    wait = int(ra) if ra else backoff(attempt)
                except Exception:
                    wait = backoff(attempt)
                LOG.warning("[THREAT] remote rate-limited; sleeping %s", wait)
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r
        except Exception as e:
            LOG.warning("[THREAT] fetch %s attempt %d failed: %s", url, attempt + 1, e)
            time.sleep(backoff(attempt))
            continue
    return None

def _load_existing() -> dict:
    try:
        with open(THREAT_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {
            "malicious_urls": [],
            "malicious_domains": [],
            "sources": {},
            "last_update": ""
        }

def _write(data: dict):
    tmp = THREAT_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    tmp.replace(THREAT_FILE)

def _extract_urls_from_openphish(text: str):
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return lines

def _extract_urls_from_phishtank_csv(text: str):
    urls = []
    for ln in (text or "").splitlines():
        m = re.search(r"https?://[^\s,]+", ln)
        if m:
            urls.append(m.group(0).strip())
    return urls

def _domain_of(url: str) -> str:
    try:
        p = urlparse(url if url.startswith("http") else "http://" + url)
        return (p.netloc or "").lower()
    except Exception:
        return ""

def main():
    LOG.info("[THREAT] starting threat update")
    existing = _load_existing()

    openphish_r = _fetch_with_retries(OPENPHISH_FEED, FETCH_TIMEOUT, FETCH_RETRIES)
    phishtank_r = _fetch_with_retries(PHISHTANK_FEED, FETCH_TIMEOUT, FETCH_RETRIES)

    openphish_urls = _extract_urls_from_openphish(openphish_r.text) if openphish_r else []
    phishtank_urls = _extract_urls_from_phishtank_csv(phishtank_r.text) if phishtank_r else []

    # merge with existing but do not hardcode seeds
    all_urls = list(dict.fromkeys((existing.get("malicious_urls") or []) + openphish_urls + phishtank_urls))
    all_domains = sorted({d for u in all_urls if (d := _domain_of(u))})

    data = {
        "malicious_urls": all_urls,
        "malicious_domains": all_domains,
        "sources": {
            "openphish": {"count": len(openphish_urls), "url": OPENPHISH_FEED},
            "phishtank": {"count": len(phishtank_urls), "url": PHISHTANK_FEED}
        },
        "last_update": datetime.datetime.utcnow().isoformat()
    }

    _write(data)
    LOG.info("[THREAT] update complete urls=%d domains=%d", len(all_urls), len(all_domains))
    print(f"Updated threat.json at {THREAT_FILE} with {len(all_urls)} urls / {len(all_domains)} domains")

if __name__ == "__main__":
    main()
