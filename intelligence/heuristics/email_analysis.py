"""
Email-specific analysis for phishing detection.
"""
import re
import logging
import email_cache
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

from gmail_utils import clean_html_for_text
from .core import score_heuristics
from .domain_utils import extract_domain_from_email
from file_analyzer import analyze_attachments

logger = logging.getLogger("heuristics.email_analysis")

def analyze_email_links_and_content(
    msg_id: Optional[str],
    subject: str,
    body: str,
    html_body: str,
    sender: str
) -> Dict[str, Any]:
    """
    Analyze email content and links for phishing indicators.
    
    Args:
        msg_id: Unique message ID for cache lookups
        subject: Email subject
        body: Plain text email body
        html_body: HTML email body
        sender: Sender email address
        
    Returns:
        Dictionary containing analysis results
    """
    # Initialize result structure
    result = {
        'label': 'safe',
        'score': 0.0,
        'explanation': '',
        'urls': [],
        'risk_links': [],
        'attachments': None
    }
    
    # Quick normalized inputs
    subj = (subject or "").strip()
    body_text = (body or "").strip()
    
    # Process HTML body if available
    html_text = ""
    if html_body:
        try:
            html_visible_text, _ = clean_html_for_text(html_body)
            html_text = (html_visible_text or "").strip()
        except Exception as e:
            logger.warning(f"Error processing HTML: {e}")
    
    # Check for empty email with attachments
    if not subj and _is_empty_content(body_text) and _is_empty_content(html_text):
        return _handle_empty_email(msg_id, result)
    
    # Extract URLs from both text and HTML
    urls = _extract_all_urls(body_text, html_text)
    
    # Prepare headers for analysis
    headers = {
        'From': sender,
        'Subject': subject,
        'URLs': urls
    }
    
    # Run heuristics
    try:
        score, explanation, risk_links = score_heuristics(
            body_text,
            headers,
            model_only=False
        )
        
        # Update result
        result.update({
            'score': float(score),
            'explanation': explanation,
            'urls': urls,
            'risk_links': risk_links
        })
        
        # Determine label based on score
        if score >= 0.7:
            result['label'] = 'phish'
        elif score >= 0.4:
            result['label'] = 'suspicious'
        
    except Exception as e:
        logger.error(f"Error in email analysis: {e}", exc_info=True)
        result.update({
            'label': 'error',
            'explanation': f'Analysis error: {str(e)}'
        })
    
    return result

def _is_empty_content(text: str) -> bool:
    """Check if text is empty or contains only placeholders."""
    if not text:
        return True
    
    norm = text.strip().lower()
    empty_indicators = [
        "(no content)",
        "no visible text",
        "no text detected",
        "file attachment detected",
        "none"
    ]
    
    return any(indicator in norm for indicator in empty_indicators) or len(norm) < 5

def _extract_all_urls(text: str, html_text: str) -> List[str]:
    """Extract and deduplicate URLs from both text and HTML."""
    urls = set()
    
    # Extract from plain text
    if text:
        urls.update(_extract_urls_from_text(text))
    
    # Extract from HTML
    if html_text:
        urls.update(_extract_urls_from_html(html_text))
    
    return list(urls)

def _extract_urls_from_text(text: str) -> List[str]:
    """Extract URLs from plain text."""
    # Simple URL pattern that catches most common cases
    url_pattern = r'https?://[^\s<>"\[\]\\]+|www\.[^\s<>"\[\]\\]+'
    return re.findall(url_pattern, text, re.IGNORECASE)

def _extract_urls_from_html(html: str) -> List[str]:
    """Extract URLs from HTML content."""
    urls = []
    
    # Simple regex to find href attributes
    href_pattern = r'href=[\'"]([^\'" >]+)[\'"]'
    matches = re.findall(href_pattern, html, re.IGNORECASE)
    
    for url in matches:
        # Clean up URL
        url = url.strip()
        if url.startswith(('http://', 'https://', 'www.')):
            urls.append(url)
    
    return urls

def _handle_empty_email(msg_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Handle the case of an email with no visible content but possibly attachments."""
    result['explanation'] = 'NO TEXT DETECTED'
    
    if not msg_id:
        return result
    
    # Check for attachments
    has_attachments = False
    attachments = []
    
    try:
        email_data = email_cache.get_cached_email(msg_id)
        if email_data and 'attachments' in email_data:
            has_attachments = bool(email_data['attachments'])
            attachments = email_data['attachments']
    except Exception as e:
        logger.warning(f"Error checking for attachments: {e}")
    
    if has_attachments:
        # Analyze attachments
        attachment_analysis = analyze_attachments(attachments)
        result['attachments'] = attachment_analysis
        
        # Update result based on attachment analysis
        if attachment_analysis.get('has_malicious', False):
            result.update({
                'label': 'phishing',
                'score': 1.0,
                'explanation': 'NO TEXT DETECTED. MALICIOUS ATTACHMENT(S) FOUND.'
            })
        elif attachment_analysis.get('has_suspicious', False):
            result.update({
                'label': 'suspicious',
                'score': 0.7,
                'explanation': 'NO TEXT DETECTED. SUSPICIOUS ATTACHMENT(S) FOUND.'
            })
        else:
            result['explanation'] = 'NO TEXT DETECTED. ATTACHMENTS APPEAR SAFE.'
    
    return result

__all__ = [
    'analyze_email_links_and_content'
]
