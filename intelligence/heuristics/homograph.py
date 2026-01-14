"""
IDN homograph detection and analysis for phishing detection.
"""
import logging
import unicodedata
from typing import Tuple, Optional, List, Dict, Any

from .domain_utils import (
    domain_from_url,
    label_contains_nonascii,
    decode_punycode,
    _registered_domain
)
from .brand_analysis import resolve_brand, find_similar_brands, get_known_brands

logger = logging.getLogger("heuristics.homograph")

def skeleton(text: str) -> str:
    """
    Normalize text for visual homograph comparison:
    - NFKC normalization
    - remove diacritics
    - lowercase
    """
    if not text:
        return ""
    
    # Normalize unicode (NFKC handles compatibility characters)
    text = unicodedata.normalize('NFKC', text)
    
    # Remove diacritics
    text = ''.join(
        c for c in unicodedata.normalize('NFD', text)
        if not unicodedata.combining(c)
    )
    
    # Convert to lowercase
    return text.lower()

def similarity(a: str, b: str) -> float:
    """Return similarity ratio (0-1) using difflib (robust fallback)."""
    from difflib import SequenceMatcher
    return SequenceMatcher(None, a, b).ratio()

def _try_resolve_brand_with_intel(hostname: str) -> Optional[str]:
    """
    Ask threat intel (if available) about a hostname or its registered domain.
    Returns canonical brand name string if intel claims impersonation/association,
    otherwise None.
    """
    if not hostname:
        return None
    
    try:
        # Try exact hostname first
        brand = resolve_brand(hostname)
        if brand:
            return brand
            
        # Try registered domain
        registered = _registered_domain(hostname)
        if registered != hostname:
            brand = resolve_brand(registered)
            if brand:
                return brand
                
    except Exception as e:
        logger.debug(f"Error in _try_resolve_brand_with_intel for {hostname}: {e}")
    
    return None

def _resolve_brand_fuzzy(hostname: str, labels_decoded: List[str]) -> Optional[Tuple[str, float]]:
    """
    Local fuzzy resolution:
    - Searches known brands in hostname (substring & label checks).
    - Uses skeleton & similarity to avoid tiny/noise matches.
    - Avoids matching on extremely short brands (<3 chars) unless exact match.
    """
    if not hostname or not labels_decoded:
        return None
    
    # Try to find similar brands in the hostname
    hostname_lower = hostname.lower()
    
    # Check each label for brand names
    for label in labels_decoded:
        if len(label) < 3:  # Skip very short labels
            continue
            
        try:
            # Find similar brands
            similar = find_similar_brands(label, threshold=0.8)
            if similar:
                brand, score = similar[0]
                if score >= 0.9 or (len(brand) >= 5 and score >= 0.8):
                    return brand, score
        except Exception as e:
            logger.warning(f"Error finding similar brands for label '{label}': {e}")
            continue
    
    return None

def check_idn_homograph(domain: str) -> Tuple[bool, str, Optional[str]]:
    """
    Detect IDN homographs, brand-modifier impersonations, and return:
      (is_impersonation_like, note, impersonated_brand_or_None)
    
    Approach:
    1. Split domain into labels and decode punycode labels.
    2. If non-ASCII present -> possible IDN homograph.
    3. Try authority intel resolution first (API).
    4. Substring detection of known brands in domain (brand-modifier).
    5. Visual similarity on main label(s) using skeleton() and similarity().
    6. Consider registered domain + subdomain hierarchy to detect subdomain impersonation.
    """
    if not domain:
        return False, "", None
    
    # 1. Split and decode labels
    labels = domain.split('.')
    labels_decoded = [decode_punycode(label) for label in labels]
    
    # 2. Check for non-ASCII characters (potential IDN)
    has_idn = any(label_contains_nonascii(label) for label in labels_decoded)
    
    # 3. Try authoritative intel first
    brand = _try_resolve_brand_with_intel(domain)
    if brand:
        return True, f"resolved as {brand} by intel", brand
    
    # 4. Local fuzzy matching
    fuzzy_brand = _resolve_brand_fuzzy(domain, labels_decoded)
    if fuzzy_brand:
        brand, score = fuzzy_brand
        return True, f"fuzzy match with {brand} (score: {score:.2f})", brand
    
    # 5. Check for brand in subdomains
    registered = _registered_domain(domain)
    if registered != domain:
        # Check if subdomain contains brand
        subdomain = domain[:-len(registered)].rstrip('.')
        fuzzy_brand = _resolve_brand_fuzzy(subdomain, [subdomain])
        if fuzzy_brand:
            brand, score = fuzzy_brand
            return True, f"subdomain '{subdomain}' similar to brand '{brand}'", brand
    
    # 6. Check for visual similarity with known brands
    domain_skeleton = skeleton(domain)
    for brand in get_known_brands():
        if len(brand) < 3:  # Skip very short brand names
            continue
            
        # Check if brand is a substring of the domain
        if brand.lower() in domain_skeleton:
            return True, f"domain contains brand name '{brand}'", brand
            
        # Check visual similarity
        brand_skeleton = skeleton(brand)
        sim = similarity(domain_skeleton, brand_skeleton)
        if sim >= 0.8:  # High threshold to reduce false positives
            return True, f"visually similar to brand '{brand}' (score: {sim:.2f})", brand
    
    return False, "", None

__all__ = [
    'skeleton',
    'similarity',
    'check_idn_homograph'
]
