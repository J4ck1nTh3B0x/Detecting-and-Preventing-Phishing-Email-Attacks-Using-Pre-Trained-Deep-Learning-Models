"""
update_whois.py

Update WHOIS cache for domains present in intelligence cache (brands/threat).
Uses DNS resolvability pre-check, retries, and cooldown on persistent failures.
Writes to ../cache/whois.json and returns counts when run programmatically.
"""

import os
import json
import time
import socket
import logging
import argparse
import datetime
from pathlib import Path
from typing import Dict, Any, Optional

LOG = logging.getLogger("update_whois")
LOG.setLevel(os.getenv("LOG_LEVEL", "INFO"))

BASE_DIR = Path(__file__).resolve().parent
CACHE_DIR = (BASE_DIR / ".." / "cache").resolve()
WHOIS_FILE = CACHE_DIR / "whois.json"
BRANDS_FILE = CACHE_DIR / "brands.json"
THREAT_FILE = CACHE_DIR / "threat.json"

CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Config driven via env
WHOIS_RETRIES = int(os.getenv("WHOIS_RETRIES", "3"))
WHOIS_COOLDOWN_SECONDS = int(os.getenv("WHOIS_COOLDOWN_SECONDS", str(60 * 60)))  # default 1 hour
WHOIS_TIMEOUT = float(os.getenv("WHOIS_TIMEOUT", "10"))

def _load(path: Path, default):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default

def _write(path: Path, data):
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    tmp.replace(path)

def normalize_domain(d: str) -> Optional[str]:
    if not d:
        return None
    s = d.strip().lower()
    if s.startswith("http://") or s.startswith("https://"):
        try:
            from urllib.parse import urlparse
            s = urlparse(s).netloc
        except Exception:
            pass
    if s.startswith("www."):
        s = s[4:]
    if " " in s or "." not in s:
        return None
    return s

def collect_domains() -> list:
    brands = _load(BRANDS_FILE, {})
    threat = _load(THREAT_FILE, {})
    collected = set()

    # Brands file may contain legit_domains
    for k in ("legit_domains", "legit_brands"):
        vals = brands.get(k) if isinstance(brands, dict) else None
        if vals:
            for v in vals:
                d = normalize_domain(v)
                if d:
                    collected.add(d)

    # Threat file may contain malicious_domains or malicious_urls
    vals = threat.get("malicious_domains") or []
    for v in vals:
        d = normalize_domain(v)
        if d:
            collected.add(d)

    # also pull domains from malicious_urls
    for u in (threat.get("malicious_urls") or []):
        try:
            from urllib.parse import urlparse
            p = urlparse(u if u.startswith("http") else "http://" + u)
            if p.netloc:
                collected.add(p.netloc.lower())
        except Exception:
            continue

    return sorted(collected)

def is_resolvable(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False

def _whois_query(domain: str) -> Dict[str, Any]:
    """
    Wrap python-whois lookup with retries. Return a dict with keys:
      domain, created, updated, registrar, country, age_days, error (optional)
    """
    try:
        import whois
    except Exception as e:
        return {"domain": domain, "error": "whois-lib-missing"}

    last_err = None
    for attempt in range(WHOIS_RETRIES):
        try:
            w = whois.whois(domain)
            # normalize extraction
            def extract_field(obj, key):
                try:
                    if isinstance(obj, dict):
                        return obj.get(key)
                    return getattr(obj, key, None)
                except Exception:
                    return None

            created = extract_field(w, "creation_date")
            updated = extract_field(w, "updated_date")
            registrar = extract_field(w, "registrar")
            country = extract_field(w, "country")

            # handle list -> pick earliest creation date if list
            import datetime as _dt
            def to_iso(v):
                if v is None:
                    return None
                if isinstance(v, list):
                    v = v[0]
                if isinstance(v, _dt.datetime):
                    return v.isoformat()
                try:
                    return str(v)
                except Exception:
                    return None

            created_iso = to_iso(created)
            updated_iso = to_iso(updated)

            age_days = None
            try:
                if created_iso:
                    dt = _dt.datetime.fromisoformat(created_iso)
                    age_days = ( _dt.datetime.utcnow() - dt ).days
            except Exception:
                age_days = None

            return {
                "domain": domain,
                "created": created_iso,
                "updated": updated_iso,
                "registrar": registrar,
                "country": country,
                "age_days": age_days,
                "error": None
            }

        except Exception as e:
            last_err = str(e)
            time.sleep(1 + attempt)
            continue

    return {"domain": domain, "error": last_err or "whois-failed"}

def update_whois(force: bool = False, max_count: Optional[int] = None):
    LOG.info("[WHOIS] starting whois update")
    data = _load(WHOIS_FILE, {"domains": {}, "last_update": ""})
    domains_cache = data.get("domains", {})

    targets = collect_domains()
    if max_count:
        targets = targets[:max_count]

    updated = 0
    failed = 0
    total = len(targets)

    for dom in targets:
        entry = domains_cache.get(dom, {})
        retry_after = entry.get("retry_after", 0)
        if not force and retry_after and retry_after > time.time():
            LOG.info("[WHOIS] skipping %s (cooldown until %s)", dom, datetime.datetime.utcfromtimestamp(retry_after).isoformat())
            continue

        if not force and entry and not entry.get("error"):
            # already have fresh data
            continue

        if not is_resolvable(dom):
            LOG.warning("[WHOIS] domain %s not resolvable; recording cooldown", dom)
            domains_cache[dom] = {"domain": dom, "error": "dns_unresolvable", "retry_after": time.time() + WHOIS_COOLDOWN_SECONDS}
            failed += 1
            continue

        info = _whois_query(dom)
        if info.get("error"):
            info["retry_after"] = time.time() + WHOIS_COOLDOWN_SECONDS
            domains_cache[dom] = info
            failed += 1
            LOG.warning("[WHOIS] whois lookup failed for %s: %s", dom, info.get("error"))
        else:
            info.pop("retry_after", None)
            domains_cache[dom] = info
            updated += 1
            LOG.info("[WHOIS] updated %s", dom)

        time.sleep(float(os.getenv("WHOIS_DELAY_SECONDS", "0.5")))

    data["domains"] = domains_cache
    data["last_update"] = datetime.datetime.utcnow().isoformat()
    _write(WHOIS_FILE, data)
    LOG.info("[WHOIS] finished updated=%d failed=%d total=%d file=%s", updated, failed, total, WHOIS_FILE)
    print(f"[whois] updated={updated}, failed={failed}, total={total}, file={WHOIS_FILE}")
    return updated, failed, total

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--max", type=int, default=0)
    args = ap.parse_args()
    update_whois(force=args.force, max_count=(args.max or None))
