"""
update_brands.py

Update brands cache used by heuristics. All config driven via environment
or existing cache files. Writes to ../cache/brands.json relative to this file.
"""

import os
import json
import time
import logging
import datetime
import requests
from pathlib import Path
from typing import List, Dict, Any

LOG = logging.getLogger("update_brands")
LOG.setLevel(os.getenv("LOG_LEVEL", "INFO"))

# Paths
BASE_DIR = Path(__file__).resolve().parent
CACHE_DIR = (BASE_DIR / ".." / "cache").resolve()
BRANDS_FILE = CACHE_DIR / "brands.json"

# Config via environment
BRANDS_SOURCE_URL = os.getenv("BRANDS_SOURCE_URL", "").strip()  # remote JSON returning brand data
FETCH_TIMEOUT = float(os.getenv("BRANDS_FETCH_TIMEOUT", "15"))
FETCH_RETRIES = int(os.getenv("BRANDS_FETCH_RETRIES", "3"))
RATE_CAPACITY = int(os.getenv("BRANDS_FETCH_RATE_CAPACITY", "10"))
RATE_PERIOD = float(os.getenv("BRANDS_FETCH_RATE_PERIOD", "60"))

# Ensure cache dir exists
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Simple token bucket (process-local) for fetch
_rate_state = {}
import threading
_rate_lock = threading.Lock()

def init_rate_bucket(key: str, capacity: int, period: float):
    with _rate_lock:
        if key not in _rate_state:
            _rate_state[key] = {"tokens": capacity, "last": time.time(), "period": period, "capacity": capacity}

def _consume_token(key: str, tokens: int = 1) -> bool:
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

init_rate_bucket("brands_fetch", RATE_CAPACITY, RATE_PERIOD)

def _load_existing() -> Dict[str, Any]:
    try:
        with open(BRANDS_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {
            "legit_brands": [],
            "legit_domains": [],
            "last_update": ""
        }

def _write(data: Dict[str, Any]):
    tmp = BRANDS_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    tmp.replace(BRANDS_FILE)

def _fetch_remote_json(url: str, timeout: float, retries: int):
    if not url:
        return None
    for attempt in range(retries):
        if not _consume_token("brands_fetch"):
            time.sleep(0.2)
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code == 429:
                ra = r.headers.get("Retry-After")
                try:
                    wait = int(ra) if ra else backoff(attempt)
                except Exception:
                    wait = backoff(attempt)
                LOG.warning("[BRANDS] remote rate-limited, sleeping %s", wait)
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r.json()
        except Exception as e:
            LOG.warning("[BRANDS] fetch attempt %d failed: %s", attempt + 1, e)
            time.sleep(backoff(attempt))
    return None

def normalize_list(items):
    out = []
    for it in (items or []):
        if not it:
            continue
        s = str(it).strip()
        if s:
            out.append(s)
    # dedupe but keep deterministic order
    seen = set()
    result = []
    for v in out:
        key = v.lower()
        if key not in seen:
            seen.add(key)
            result.append(v)
    return result

def main():
    LOG.info("[BRANDS] starting update")
    existing = _load_existing()

    # 1) try remote JSON if configured
    remote = None
    if BRANDS_SOURCE_URL:
        LOG.info("[BRANDS] fetching remote source from %s", BRANDS_SOURCE_URL)
        remote = _fetch_remote_json(BRANDS_SOURCE_URL, FETCH_TIMEOUT, FETCH_RETRIES)
        if remote is None:
            LOG.warning("[BRANDS] remote fetch returned nothing or failed")

    # 2) build merged lists using existing cache as base
    legit_brands = normalize_list(existing.get("legit_brands", []))
    legit_domains = normalize_list(existing.get("legit_domains", []))

    # remote may supply {"legit_brands": [...], "legit_domains": [...]} or a flat list
    if remote:
        if isinstance(remote, dict):
            remote_brands = normalize_list(remote.get("legit_brands", []))
            remote_domains = normalize_list(remote.get("legit_domains", []))
        elif isinstance(remote, list):
            # assume list of domains or names; separate by presence of dot
            remote_brands = [x for x in normalize_list(remote) if "." not in x]
            remote_domains = [x for x in normalize_list(remote) if "." in x]
        else:
            remote_brands = []
            remote_domains = []
    else:
        remote_brands = []
        remote_domains = []

    # Merge without hard-coded seeds
    merged_brands = normalize_list(legit_brands + remote_brands)
    merged_domains = normalize_list(legit_domains + remote_domains)

    data = {
        "legit_brands": merged_brands,
        "legit_domains": merged_domains,
        "last_update": datetime.datetime.utcnow().isoformat()
    }

    _write(data)
    LOG.info("[BRANDS] update complete. brands=%d domains=%d", len(merged_brands), len(merged_domains))
    print(f"Updated brands.json at {BRANDS_FILE}")

if __name__ == "__main__":
    main()
