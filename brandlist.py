# brandlist.py
import json
from pathlib import Path
from urllib.parse import urlparse

CACHE_FILE = Path(__file__).resolve().parent / "intelligence" / "cache" / "brands.json"

def load_brands():
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            brands = list(data.keys())
            domains = []
            for info in data.values():
                domains.extend(info.get("domains", []))
            return brands, domains
    except Exception as e:
        print(f"[brandlist] Failed to load cache: {e}")
        return [], []

def get_known_brands():
    brands, _ = load_brands()
    return brands

def get_known_domains():
    _, domains = load_brands()
    return domains

def domain_from_url(u: str) -> str:
    """
    Extract domain/hostname from a URL or raw string safely.
    This helper is used by heuristics and brand similarity checks.
    """
    try:
        if not isinstance(u, str):
            return ""
        if not u.lower().startswith(("http://", "https://")):
            u = "https://" + u
        p = urlparse(u)
        return (p.hostname or "").lower()
    except Exception:
        return ""
