import json
import logging
import os
import re
import time
import threading
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any, Callable
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

log = logging.getLogger("brandlist")

# Path configuration
CACHE_DIR = Path(__file__).parent / "cache"
BRANDS_JSON = CACHE_DIR / "brands.json"
THREAT_JSON = CACHE_DIR / "threat.json"

@dataclass
class BrandCache:
    brands: Set[str] = None
    domains: Set[str] = None
    brand_to_domains: Dict[str, List[str]] = None
    domain_to_brand: Dict[str, str] = None
    last_modified: float = 0
    last_checked: float = 0
    _lock: threading.RLock = threading.RLock()
    _callbacks: List[Callable] = None

    def __post_init__(self):
        self.brands = set()
        self.domains = set()
        self.brand_to_domains = {}
        self.domain_to_brand = {}
        self._callbacks = []

    def update(self, brands: Set[str], domains: Set[str], 
              brand_to_domains: Dict[str, List[str]], 
              domain_to_brand: Dict[str, str],
              last_modified: float):
        with self._lock:
            self.brands = brands
            self.domains = domains
            self.brand_to_domains = brand_to_domains
            self.domain_to_brand = domain_to_brand
            self.last_modified = last_modified
            self.last_checked = time.time()
            self._notify_callbacks()
    
    def add_callback(self, callback: Callable):
        with self._lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)
    
    def remove_callback(self, callback: Callable):
        with self._lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)
    
    def _notify_callbacks(self):
        with self._lock:
            for callback in self._callbacks:
                try:
                    callback()
                except Exception as e:
                    log.error(f"Error in cache callback: {e}")

# Global cache instance
_brand_cache = BrandCache()

class BrandFileHandler(FileSystemEventHandler):
    """Watch for changes to brands.json and update cache."""
    def __init__(self, callback: Callable):
        self.callback = callback
        self.last_handled = 0
    
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('brands.json'):
            # Avoid multiple rapid updates
            current_time = time.time()
            if current_time - self.last_handled > 1.0:  # 1 second debounce
                self.last_handled = current_time
                log.info("Brands file modified, updating cache...")
                try:
                    self.callback()
                except Exception as e:
                    log.error(f"Error updating brand cache: {e}")

# File watcher for live updates
_file_observer = None
_file_handler = None
def _start_file_watcher():
    global _file_observer, _file_handler
    if _file_observer is not None:
        return
    
    try:
        _file_observer = Observer()
        _file_handler = BrandFileHandler(_update_brand_cache)
        _file_observer.schedule(_file_handler, str(CACHE_DIR), recursive=False)
        _file_observer.daemon = True
        _file_observer.start()
        log.info("Started brand file watcher")
    except Exception as e:
        log.error(f"Failed to start file watcher: {e}")

def _stop_file_watcher():
    global _file_observer
    if _file_observer:
        try:
            _file_observer.stop()
            _file_observer.join()
            _file_observer = None
        except Exception as e:
            log.error(f"Error stopping file watcher: {e}")

# Register cleanup on exit
import atexit
atexit.register(_stop_file_watcher)

def _load_json(path: Path) -> tuple[dict, float]:
    """Safely load JSON data from a file with modification time."""
    try:
        if not path.exists():
            log.warning(f"[brandlist] File not found: {path}")
            return {}, 0
        
        mtime = path.stat().st_mtime
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), mtime
    except Exception as e:
        log.error(f"[brandlist] Failed to load {path}: {str(e)}")
        return {}, 0

def _normalize_brand_name(name: str) -> str:
    """Normalize brand name for consistent comparison."""
    if not name:
        return ""
    return name.strip().lower()

def _extract_domain(url: str) -> str:
    """Extract domain from URL."""
    if not url:
        return ""
    # Remove protocol and path
    domain = url.split("://")[-1].split("/")[0]
    # Remove port if present
    domain = domain.split(":")[0]
    # Remove www. prefix
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.lower()

def _load_brands_data() -> tuple[Dict[str, Any], float]:
    """Load and parse brands data, returning data and file modification time."""
    data, mtime = _load_json(BRANDS_JSON)
    if not data:
        log.warning("[brandlist] No brand data loaded")
        return {}, 0
    return data, mtime

def _build_brand_mappings(data: dict) -> tuple:
    """Build brand and domain mappings from raw data."""
    brands = set()
    domains = set()
    brand_to_domains = {}
    domain_to_brand = {}

    for brand_name, brand_data in data.items():
        if not brand_name:
            continue
        
        normalized_brand = _normalize_brand_name(brand_name)
        if not normalized_brand:
            continue
            
        brands.add(normalized_brand)
        brand_domains = set()
        
        # Extract domains from brand data
        for domain in brand_data.get("domains", []):
            normalized_domain = _extract_domain(domain)
            if normalized_domain:
                domains.add(normalized_domain)
                brand_domains.add(normalized_domain)
                domain_to_brand[normalized_domain] = normalized_brand
        
        if brand_domains:
            brand_to_domains[normalized_brand] = list(brand_domains)
    
    return brands, domains, brand_to_domains, domain_to_brand

def _update_brand_cache(force: bool = False):
    """Update the brand cache if needed or forced."""
    global _brand_cache
    
    data, mtime = _load_brands_data()
    if not data:
        return
    
    with _brand_cache._lock:
        current_time = time.time()
        
        # Check if update is needed
        if not force and mtime <= _brand_cache.last_modified:
            # Update last_checked even if we don't update the data
            _brand_cache.last_checked = current_time
            return False
        
        # Build new cache data
        brands, domains, brand_to_domains, domain_to_brand = _build_brand_mappings(data)
        
        # Update cache
        _brand_cache.update(
            brands=brands,
            domains=domains,
            brand_to_domains=brand_to_domains,
            domain_to_brand=domain_to_brand,
            last_modified=mtime
        )
        
        log.info(f"[brandlist] Updated brand cache with {len(brands)} brands and {len(domains)} domains")
        return True

def refresh_brand_cache() -> bool:
    """Force a refresh of the brand cache."""
    return _update_brand_cache(force=True)

def get_known_brands() -> List[str]:
    """Get a list of all known brand names."""
    _update_brand_cache()
    with _brand_cache._lock:
        return list(_brand_cache.brands or [])

def get_known_domains() -> List[str]:
    """Get a list of all known brand domains."""
    _update_brand_cache()
    with _brand_cache._lock:
        return list(_brand_cache.domains or [])

def get_brand_for_domain(domain: str) -> Optional[str]:
    """Get the brand associated with a domain, if any."""
    if not domain:
        return None
    _update_brand_cache()
    with _brand_cache._lock:
        return _brand_cache.domain_to_brand.get(_extract_domain(domain))

def get_domains_for_brand(brand: str) -> List[str]:
    """Get all domains associated with a brand."""
    if not brand:
        return []
    _update_brand_cache()
    with _brand_cache._lock:
        return _brand_cache.brand_to_domains.get(_normalize_brand_name(brand), [])

def is_brand_domain(domain: str) -> bool:
    """Check if a domain is associated with any known brand."""
    if not domain:
        return False
    _update_brand_cache()
    with _brand_cache._lock:
        return _extract_domain(domain) in (_brand_cache.domains or set())

def find_similar_brands(query: str, threshold: float = 0.8) -> List[Tuple[str, float]]:
    """Find brands similar to the query string using fuzzy matching."""
    from difflib import SequenceMatcher
    
    if not query:
        return []
    
    query = _normalize_brand_name(query)
    _update_brand_cache()
    
    results = []
    with _brand_cache._lock:
        for brand in (_brand_cache.brands or []):
            ratio = SequenceMatcher(None, query, brand).ratio()
            if ratio >= threshold:
                results.append((brand, ratio))
    
    return sorted(results, key=lambda x: x[1], reverse=True)

# Initialize cache on module load
_update_brand_cache()

# Start the file watcher for live updates
_start_file_watcher()
