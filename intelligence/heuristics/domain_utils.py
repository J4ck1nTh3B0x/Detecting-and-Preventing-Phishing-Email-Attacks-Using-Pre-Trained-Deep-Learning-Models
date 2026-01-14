"""
Domain and URL handling utilities for heuristics analysis.
"""
import re
import socket
from typing import Optional, List, Tuple
from urllib.parse import urlparse

import requests
import tldextract

# Optional: prefer tldextract for robust domain extraction if available
try:
    _tld_extractor = tldextract.TLDExtract(suffix_list_urls=None)
    _HAS_TLDEXTRACT = True
except Exception:
    _HAS_TLDEXTRACT = False

def domain_from_url(u: str) -> str:
    """Extract domain from URL."""
    if not u:
        return ""
    # Remove protocol and path
    domain = u.split("://")[-1].split("/")[0]
    # Remove port if present
    domain = domain.split(":")[0]
    # Remove www. prefix
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.lower()

def extract_domain_host(url: str) -> str:
    """
    Extract and validate the host/domain for security checks.
    Handles IDN, punycode, and attempts to detect domain spoofing.
    """
    if not url:
        return ""
    
    # Handle hxxp obfuscation
    url = url.replace('hxxp', 'http')
    
    try:
        # First try tldextract if available
        if _HAS_TLDEXTRACT:
            extracted = _tld_extractor(url)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}".lower()
        
        # Fallback to manual parsing
        parsed = urlparse(url if '//' in url else f'//{url}')
        hostname = parsed.netloc or parsed.path.split('/')[0]
        
        # Remove port if present
        hostname = hostname.split(':')[0]
        
        # Basic validation
        if not hostname or len(hostname) > 253 or any(len(part) > 63 for part in hostname.split('.')):
            return ""
            
        # Try to resolve to catch obvious typosquatting
        try:
            socket.gethostbyname(hostname)
        except (socket.gaierror, UnicodeError):
            pass
            
        return hostname.lower()
        
    except Exception as e:
        return ""

def _registered_domain(hostname: str) -> str:
    """Return the registered (effective second-level) domain for hierarchy checks."""
    if not hostname:
        return ""
    
    if _HAS_TLDEXTRACT:
        extracted = _tld_extractor(hostname)
        if extracted.registered_domain:
            return extracted.registered_domain.lower()
    
    # Fallback: take last two parts
    parts = hostname.split('.')
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}".lower()
    return hostname.lower()

def is_reachable(url: str) -> bool:
    """
    Lightweight reachability test using HEAD → fallback GET.
    Does NOT follow dangerous redirects and never raises exceptions.
    """
    if not url or not (url.startswith('http://') or url.startswith('https://')):
        return False
        
    try:
        # Try HEAD first
        response = requests.head(
            url,
            timeout=10,
            allow_redirects=False,
            verify=True,
            headers={'User-Agent': 'PhishingDetector/1.0'}
        )
        return response.status_code < 400
        
    except requests.RequestException:
        # Fallback to GET if HEAD fails
        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=False,
                verify=True,
                headers={'User-Agent': 'PhishingDetector/1.0'}
            )
            return response.status_code < 400
        except Exception:
            return False
    except Exception:
        return False

def extract_domain_from_email(addr: str) -> str:
    """Extract the domain portion from an email address."""
    if not addr or '@' not in addr:
        return ""
    return addr.split('@', 1)[1].lower()

def decode_punycode(label: str) -> str:
    """Decode punycode/IDN labels."""
    if not label:
        return ""
    try:
        return label.encode('ascii').decode('idna')
    except (UnicodeError, LookupError):
        return label

def label_contains_nonascii(label: str) -> bool:
    """Detect non-ASCII characters in a label (potential IDN)."""
    return any(ord(c) > 127 for c in label)

__all__ = [
    'domain_from_url',
    'extract_domain_host',
    '_registered_domain',
    'is_reachable',
    'extract_domain_from_email',
    'decode_punycode',
    'label_contains_nonascii'
]
