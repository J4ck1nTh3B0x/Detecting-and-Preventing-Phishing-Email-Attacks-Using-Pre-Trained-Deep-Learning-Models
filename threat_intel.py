"""
threat_intel.py

Threat intelligence helpers including VT/GSB enrichment and brand resolution.
Uses live_config for automatic updates of data files.

Behavior:
 - Attempt API resolution if BRAND_RESOLVE_API_URL is set (expects JSON with 'brand' or 'name').
 - Cache results using live_config system with automatic file watching.
 - Rate-limited and retries configurable via environment.
 - If API fails or not configured, fallback to local brandlist.get_known_brands() fuzzy match.
 - Exposes intel_enrich(urls) and resolve_brand(domain).
"""

import os
import sys
import json
import time
import logging
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from urllib.parse import urlparse

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Try to import required modules with fallbacks
try:
    import requests
except ImportError:
    logging.warning("requests module not found. Some features may be limited.")
    requests = None

# Import live_config for file watching and caching
try:
    from intelligence.live_config import load_file, watch_file, get_file_cache
except ImportError as e:
    logging.warning(f"Failed to import live_config: {e}")
    # Provide dummy implementations for live_config functions
    def load_file(*args, **kwargs):
        return {}
    
    def watch_file(*args, **kwargs):
        pass
    
    def get_file_cache(*args, **kwargs):
        return {}

logger = logging.getLogger("threat_intel")
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

# Config via env (no hard-coded values)
BRAND_RESOLVE_API_URL = os.getenv("BRAND_RESOLVE_API_URL", "").strip()
BRAND_RESOLVE_TIMEOUT = float(os.getenv("BRAND_RESOLVE_TIMEOUT", "5"))
BRAND_RESOLVE_RETRIES = int(os.getenv("BRAND_RESOLVE_RETRIES", "2"))
BRAND_RESOLVE_RATE_CAPACITY = int(os.getenv("BRAND_RESOLVE_RATE_CAPACITY", "5"))
BRAND_RESOLVE_RATE_PERIOD = float(os.getenv("BRAND_RESOLVE_RATE_PERIOD", "60"))

# If threat_intel already provides other functions, keep them; we'll not remove
try:
    # existing function placeholder - keep backwards compatibility if present
    from threat_intel import intel_enrich as _intel_enrich_orig  # type: ignore
    has_orig_intel_enrich = True
except Exception:
    has_orig_intel_enrich = False
    _intel_enrich_orig = None  # type: ignore

# Fallback to local brandlist if needed
try:
    from intelligence.brandlist import get_known_brands
except ImportError as e:
    logging.warning(f"Failed to import brandlist: {e}")
    def get_known_brands():
        logging.warning("brandlist module not found, using empty brand list")
        return []

# --- Rate Limiter using live_config ---------------------------------------
class RateLimiter:
    """Thread-safe rate limiter using token bucket algorithm."""
    def __init__(self, capacity: int, period: float):
        self.capacity = capacity
        self.period = period
        self.tokens = capacity
        self.last_update = time.time()
        self.lock = threading.RLock()

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens, returns True if successful."""
        with self.lock:
            now = time.time()
            time_passed = now - self.last_update
            self.last_update = now
            
            # Add tokens based on time passed
            new_tokens = (time_passed / self.period) * self.capacity
            self.tokens = min(self.capacity, self.tokens + new_tokens)
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

# Initialize rate limiters
brand_resolve_limiter = RateLimiter(
    capacity=BRAND_RESOLVE_RATE_CAPACITY,
    period=BRAND_RESOLVE_RATE_PERIOD
)

# --- Cache Management using live_config ------------------------------------
# Get cache instances
brand_resolve_cache = get_file_cache(
    Path("intelligence/cache/brand_resolve_cache.json"),
    default={"domains": {}, "last_update": None}
)

# Watch for changes to the cache file
def _on_brand_cache_updated(new_data: dict):
    """Handle updates to the brand resolve cache."""
    if not isinstance(new_data, dict):
        logger.warning("Invalid cache data format, resetting to default")
        new_data = {"domains": {}, "last_update": None}
    
    # Ensure required fields exist
    if "domains" not in new_data:
        new_data["domains"] = {}
    if "last_update" not in new_data:
        new_data["last_update"] = None
    
    logger.debug(f"Brand cache updated, {len(new_data.get('domains', {}))} entries")

# Set up the watcher for the cache file
watch_file(
    Path("intelligence/cache/brand_resolve_cache.json"),
    _on_brand_cache_updated
)

# --- brand resolution ------------------------------------------------------
def _call_brand_api(domain: str) -> Optional[str]:
    """Call external brand resolve API (if configured). Returns brand name or None."""
    if not BRAND_RESOLVE_API_URL or not domain:
        return None
    
    # Check rate limiting
    if not brand_resolve_limiter.consume():
        logger.debug(f"Rate limited: {domain}")
        return None
    
    logger.debug(f"Querying brand API for: {domain}")
    
    for attempt in range(BRAND_RESOLVE_RETRIES + 1):
        try:
            response = requests.get(
                BRAND_RESOLVE_API_URL,
                params={"domain": domain},
                timeout=BRAND_RESOLVE_TIMEOUT,
                headers={"User-Agent": "PhishingDetector/1.0"}
            )
            response.raise_for_status()
            
            # Try to parse brand from common response formats
            data = response.json()
            if not data:
                return None
                
            # Check common response formats
            brand = data.get('brand') or data.get('name')
            if brand:
                return str(brand).strip()
                
            # If we have a direct string response
            if isinstance(data, str):
                return data.strip()
                
            return None
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"Brand API attempt {attempt + 1} failed: {e}")
            if attempt == BRAND_RESOLVE_RETRIES:
                logger.warning(f"Failed to resolve brand for {domain} after {BRAND_RESOLVE_RETRIES} attempts")
                return None
            time.sleep(1)  # Simple backoff
            
    return None

def _normalize_domain_candidate(s: str) -> str:
    try:
        s = s.strip().lower()
        if s.startswith("http://") or s.startswith("https://"):
            p = urlparse(s)
            return (p.netloc or "").lower()
        if s.startswith("www."):
            return s[4:]
        return s
    except Exception:
        return s.lower()

def _fuzzy_local_brand_match(domain: str) -> Optional[str]:
    """Fallback fuzzy match against local brand list. Returns brand or None."""
    brands = get_known_brands() or []
    dd = _normalize_domain_candidate(domain)
    # attempt substring match first
    for b in brands:
        if not b:
            continue
        b_low = str(b).lower()
        if b_low in dd and dd != b_low:
            return b
    # visual similarity on main label
    try:
        main_label = dd.split(".")[0]
    except Exception:
        main_label = dd
    # lightweight similarity (difflib)
    import difflib
    best = None
    best_ratio = 0.0
    for b in brands:
        try:
            r = difflib.SequenceMatcher(None, main_label, str(b).lower()).ratio()
            if r > best_ratio and r > float(os.getenv("BRAND_FUZZY_THRESHOLD", "0.80")):
                best_ratio = r
                best = b
        except Exception:
            continue
    return best

def resolve_brand(domain: str) -> Optional[str]:
    """
    Public resolver: API-first, then cache, then local fallback.
    Uses live_config for cache management and automatic updates.
    Returns a brand name string or None.
    """
    if not domain:
        return None
        
    # Normalize domain
    domain = _normalize_domain_candidate(domain)
    if not domain:
        return None
    
    # Get current cache state (automatically updated by live_config)
    cache = brand_resolve_cache.data
    if not isinstance(cache, dict):
        logger.warning("Invalid cache format, resetting")
        cache = {"domains": {}, "last_update": None}
        brand_resolve_cache.data = cache
    
    # Check if we have a valid cached result
    cache_domains = cache.get("domains", {})
    if not isinstance(cache_domains, dict):
        cache_domains = {}
        cache["domains"] = cache_domains
    
    cached_entry = cache_domains.get(domain, {})
    if isinstance(cached_entry, dict) and "brand" in cached_entry:
        if cached_entry.get("expires", 0) > time.time():
            return cached_entry["brand"]
    
    # Try API if configured
    brand = None
    if BRAND_RESOLVE_API_URL:
        brand = _call_brand_api(domain)
    
    # Fallback to fuzzy matching if API fails or not configured
    if not brand:
        brand = _fuzzy_local_brand_match(domain)
    
    # Update cache if we got a result
    if brand:
        with brand_resolve_cache._lock:
            # Get fresh cache state in case it was updated
            cache = brand_resolve_cache.data
            if not isinstance(cache, dict):
                cache = {"domains": {}, "last_update": None}
            
            if "domains" not in cache:
                cache["domains"] = {}
            
            cache["domains"][domain] = {
                "brand": brand,
                "resolved_at": time.time(),
                "expires": time.time() + (30 * 24 * 3600),  # 30 days TTL
                "source": "api" if BRAND_RESOLVE_API_URL and brand else "fuzzy"
            }
            cache["last_update"] = time.time()
            
            # Save the updated cache
            brand_resolve_cache.data = cache
            
            # Write to disk (this will trigger the file watcher)
            try:
                import json
                with open(brand_resolve_cache.path, 'w') as f:
                    json.dump(cache, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to write brand cache: {e}")
    
    return brand

# --- Threat Intelligence Enrichment --------------------------------------
# This is a simplified implementation that can be extended with more services

def intel_enrich(urls: List[str]) -> List[Dict]:
    """
    Enrich URLs with threat intelligence data.
    Returns a list of enrichment results matching the input URLs.
    """
    if not urls:
        return []
    
    results = []
    
    for url in urls:
        result = {
            "url": url,
            "malicious": False,
            "suspicious": False,
            "brand": None,
            "sources": []
        }
        
        try:
            # Extract domain for brand resolution
            domain = _normalize_domain_candidate(url)
            if domain:
                # Resolve brand if possible
                brand = resolve_brand(domain)
                if brand:
                    result["brand"] = brand
                    result["sources"].append("brand_resolution")
            
            # Add more threat intelligence checks here as needed
            # Example: Check against local threat feeds, external APIs, etc.
            
        except Exception as e:
            logger.error(f"Error enriching URL {url}: {e}")
        
        results.append(result)
    
    return results

# --- legacy intel_enrich wrapper (preserve original if present) -----------
def intel_enrich_legacy(urls: List[str]) -> List[Dict[str, Any]]:
    """
    If a prior intel_enrich implementation exists use it. Otherwise provide
    a lightweight no-op that returns an empty list. This keeps compatibility.
    """
    if has_orig_intel_enrich and callable(_intel_enrich_orig):
        try:
            return _intel_enrich_orig(urls)
        except Exception as e:
            logger.exception("[TI] original intel_enrich failed: %s", e)
            return []
    # fallback noop
    return []
