"""
Brand detection and analysis for phishing detection.
"""
import logging
import time
import threading
from typing import List, Tuple, Optional, Set, Dict, Any

logger = logging.getLogger("heuristics.brand_analysis")

# Import brandlist functions
# Try to import from brandlist with better error handling
_import_errors = []
_brandlist_available = False

try:
    from intelligence.brandlist import (
        get_known_brands as _get_brands,
        get_known_domains as _get_domains,
        get_brand_for_domain as _get_brand_for_domain,
        is_brand_domain as _is_brand_domain,
        find_similar_brands as _find_similar_brands,
        refresh_brand_cache as _refresh_brand_cache
    )
    _brandlist_available = True
    
    # Wrap functions with error handling
    def get_known_brands() -> List[str]:
        try:
            return _get_brands() or []
        except Exception as e:
            logger.warning(f"Error in get_known_brands: {e}")
            return []
            
    def get_known_domains() -> List[str]:
        try:
            return _get_domains() or []
        except Exception as e:
            logger.warning(f"Error in get_known_domains: {e}")
            return []
            
    def get_brand_for_domain(domain: str) -> Optional[str]:
        try:
            return _get_brand_for_domain(domain)
        except Exception as e:
            logger.warning(f"Error in get_brand_for_domain: {e}")
            return None
            
    def is_brand_domain(domain: str) -> bool:
        try:
            return bool(_is_brand_domain(domain))
        except Exception as e:
            logger.warning(f"Error in is_brand_domain: {e}")
            return False
            
    def find_similar_brands(query: str, threshold: float = 0.8) -> List[Tuple[str, float]]:
        try:
            return _find_similar_brands(query, threshold) or []
        except Exception as e:
            logger.warning(f"Error in find_similar_brands: {e}")
            return []
            
    def refresh_brand_cache() -> bool:
        try:
            return bool(_refresh_brand_cache())
        except Exception as e:
            logger.warning(f"Error refreshing brand cache: {e}")
            return False

except ImportError as e:
    _import_errors.append(f"Failed to import brandlist module: {e}")
    _brandlist_available = False
    logger.error(f"Failed to import brandlist module: {e}")
    
    # Fallback implementations if brandlist module is not available
    _known_brands_cache = set()
    _known_domains_cache = set()
    _brand_to_domains = {}
    _domain_to_brand = {}
    _last_brand_update = 0
    _cache_lock = threading.RLock()
    _brand_resolution_cache = {}
    _brandlist_available = False
    
    def _update_known_brands_cache():
        """Fallback implementation that loads from a basic list"""
        global _known_brands_cache, _last_brand_update, _known_domains_cache, _brand_to_domains, _domain_to_brand
        
        current_time = time.time()
        if current_time - _last_brand_update < 3600:  # Update at most once per hour
            return
            
        with _cache_lock:
            try:
                _last_brand_update = current_time
                
                # Basic list of common brands
                common_brands = {
                    'google': ['google.com', 'gmail.com', 'youtube.com', 'googlemail.com'],
                    'microsoft': ['microsoft.com', 'outlook.com', 'live.com', 'office365.com'],
                    'apple': ['apple.com', 'icloud.com', 'me.com', 'appleid.apple.com'],
                    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.ca'],
                    'facebook': ['facebook.com', 'fb.com', 'messenger.com', 'instagram.com'],
                    'netflix': ['netflix.com'],
                    'paypal': ['paypal.com', 'paypal.me'],
                    'linkedin': ['linkedin.com', 'lnkd.in'],
                    'twitter': ['twitter.com', 'x.com', 't.co'],
                    'dropbox': ['dropbox.com', 'db.tt'],
                }
                
                # Update caches
                _known_brands_cache = set(common_brands.keys())
                _brand_to_domains = common_brands.copy()
                
                # Build reverse mapping
                _domain_to_brand = {}
                _known_domains_cache = set()
                
                for brand, domains in common_brands.items():
                    for domain in domains:
                        _domain_to_brand[domain] = brand
                        _known_domains_cache.add(domain)
                        
                logger.info(f"Updated brand cache with {len(_known_brands_cache)} brands and {len(_known_domains_cache)} domains")
                
            except Exception as e:
                logger.error(f"Error updating brand cache: {e}")
                # Ensure we have at least empty collections on error
                _known_brands_cache = set()
                _known_domains_cache = set()
                _brand_to_domains = {}
                _domain_to_brand = {}
    
    def get_known_brands() -> List[str]:
        """Fallback implementation that returns an empty list"""
        return list(_known_brands_cache)
        
    def get_known_domains() -> List[str]:
        """Get a list of all known brand domains."""
        _update_known_brands_cache()
        with _cache_lock:
            return list(_known_domains_cache)
        
    def get_brand_for_domain(domain: str) -> Optional[str]:
        """Get the brand associated with a domain, if any."""
        if not domain:
            return None
            
        _update_known_brands_cache()
        
        # Normalize domain (remove www. and convert to lowercase)
        domain = domain.lower().replace('www.', '')
        
        with _cache_lock:
            # Check exact match first
            if domain in _domain_to_brand:
                return _domain_to_brand[domain]
                
            # Check subdomains
            parts = domain.split('.')
            for i in range(1, len(parts)):
                subdomain = '.'.join(parts[i:])
                if subdomain in _domain_to_brand:
                    return _domain_to_brand[subdomain]
                    
        return None
        
    def is_brand_domain(domain: str) -> bool:
        """Check if a domain is associated with a known brand."""
        return get_brand_for_domain(domain) is not None
        
    def find_similar_brands(query: str, threshold: float = 0.8) -> List[Tuple[str, float]]:
        """Find brands similar to the query string."""
        if not query or not query.strip():
            return []
            
        _update_known_brands_cache()
        
        query = query.lower().strip()
        results = []
        
        with _cache_lock:
            for brand in _known_brands_cache:
                score = _similarity(query, brand.lower())
                if score >= threshold:
                    results.append((brand, score))
                    
        # Sort by score descending
        results.sort(key=lambda x: x[1], reverse=True)
        return results
        
    def refresh_brand_cache() -> bool:
        """Force a refresh of the brand cache."""
        with _cache_lock:
            global _last_brand_update
            _last_brand_update = 0
            _update_known_brands_cache()
            return True

def is_brand_domain(domain: str) -> bool:
    """
    Check if a domain is associated with any known brand.
    
    Args:
        domain: The domain to check
        
    Returns:
        bool: True if the domain is associated with a known brand, False otherwise
    """
    if not domain:
        return False
    
    # Use the implementation from brandlist if available
    if '_is_brand_domain' in globals():
        try:
            return _is_brand_domain(domain)
        except Exception as e:
            logger.warning(f"Error in is_brand_domain: {e}")
            return False
    
    # Fallback implementation
    if not hasattr(is_brand_domain, '_known_brands'):
        try:
            is_brand_domain._known_brands = set(get_known_brands() or [])
        except Exception as e:
            logger.warning(f"Error getting known brands: {e}")
            is_brand_domain._known_brands = set()
    
    domain = domain.lower()
    
    # Check exact match
    if domain in is_brand_domain._known_brands:
        return True
        
    # Check subdomains (e.g., subdomain.brand.com)
    parts = domain.split('.')
    for i in range(1, len(parts)):
        if '.'.join(parts[i:]) in is_brand_domain._known_brands:
            return True
            
    return False

def get_brand_for_domain(domain: str) -> Optional[str]:
    """
    Get the brand associated with a domain, if any.
    
    Args:
        domain: The domain to look up
        
    Returns:
        Optional[str]: The brand name if found, None otherwise
    """
    if not domain:
        return None
    
    # Use the implementation from brandlist if available
    if '_get_brand_for_domain' in globals():
        try:
            return _get_brand_for_domain(domain)
        except Exception as e:
            logger.warning(f"Error in get_brand_for_domain: {e}")
            return None
    
    # Fallback implementation
    if not hasattr(get_brand_for_domain, '_known_brands'):
        try:
            get_brand_for_domain._known_brands = set(get_known_brands() or [])
        except Exception as e:
            logger.warning(f"Error getting known brands: {e}")
            get_brand_for_domain._known_brands = set()
    
    domain = domain.lower()
    
    # Check cache first
    if not hasattr(get_brand_for_domain, '_cache'):
        get_brand_for_domain._cache = {}
    
    if domain in get_brand_for_domain._cache:
        return get_brand_for_domain._cache[domain]
    
    # Check exact match
    if domain in get_brand_for_domain._known_brands:
        get_brand_for_domain._cache[domain] = domain
        return domain
        
    # Check subdomains (e.g., subdomain.brand.com)
    parts = domain.split('.')
    for i in range(1, len(parts)):
        potential_brand = '.'.join(parts[i:])
        if potential_brand in get_brand_for_domain._known_brands:
            get_brand_for_domain._cache[domain] = potential_brand
            return potential_brand
    
    # No match found
    get_brand_for_domain._cache[domain] = None
    return None

def find_similar_brands(query: str, threshold: float = 0.8) -> List[Tuple[str, float]]:
    """
    Find brands similar to the query string.
    
    Args:
        query: The query string to find similar brands for
        threshold: Minimum similarity score (0.0 to 1.0)
        
    Returns:
        List[Tuple[str, float]]: List of (brand, score) tuples, sorted by score descending
    """
    # Use the implementation from brandlist if available
    if '_find_similar_brands' in globals():
        try:
            return _find_similar_brands(query, threshold)
        except Exception as e:
            logger.warning(f"Error in find_similar_brands: {e}")
            return []
    
    # Fallback implementation
    if not query:
        return []
        
    if not hasattr(find_similar_brands, '_known_brands'):
        try:
            find_similar_brands._known_brands = set(get_known_brands() or [])
        except Exception as e:
            logger.warning(f"Error getting known brands: {e}")
            find_similar_brands._known_brands = set()
    
    if not find_similar_brands._known_brands:
        return []
        
    query = query.lower()
    results = []
    
    for brand in find_similar_brands._known_brands:
        try:
            score = _similarity(query, brand.lower())
            if score >= threshold:
                results.append((brand, score))
        except Exception as e:
            logger.debug(f"Error calculating similarity for brand {brand}: {e}")
    
    # Sort by score descending
    return sorted(results, key=lambda x: x[1], reverse=True)

def _similarity(a: str, b: str) -> float:
    """Calculate similarity between two strings (0-1)."""
    if not a or not b:
        return 0.0
        
    a = a.lower().strip()
    b = b.lower().strip()
    
    # Quick check for exact match
    if a == b:
        return 1.0
        
    # Check for substring match
    if a in b or b in a:
        return 0.9
        
    # Use difflib for more complex comparison
    try:
        from difflib import SequenceMatcher
        return SequenceMatcher(None, a, b).ratio()
    except Exception:
        return 0.0

# Brand resolution from threat intel if available
try:
    from threat_intel import resolve_brand as _threat_intel_resolve_brand
    
    def resolve_brand(domain: str) -> Optional[str]:
        """
        Resolve brand using threat intel if available, fallback to local cache.
        
        Args:
            domain: The domain to resolve
            
        Returns:
            Optional[str]: The resolved brand name or None if not found
        """
        try:
            # Try threat intel first
            result = _threat_intel_resolve_brand(domain)
            if result:
                return result
        except Exception as e:
            logger.debug(f"Error resolving brand from threat intel: {e}")
        
        # Fall back to local cache
        return get_brand_for_domain(domain)
            
except ImportError:
    # Fallback to local resolution only if threat_intel is not available
    def resolve_brand(domain: str) -> Optional[str]:
        """Resolve brand using local cache only."""
        return get_brand_for_domain(domain)

__all__ = [
    'get_known_brands',
    'is_brand_domain',
    'get_brand_for_domain',
    'find_similar_brands',
    'resolve_brand'
]
