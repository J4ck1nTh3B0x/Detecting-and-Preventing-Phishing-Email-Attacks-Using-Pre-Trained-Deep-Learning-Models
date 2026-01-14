import os
import re
import logging
import logging.config
try:
    import magic
    MAGIC_AVAILABLE = True
except (ImportError, OSError):
    MAGIC_AVAILABLE = False
    logging.warning("python-magic is not available. File type detection will be limited.")
import olefile
import io
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set, BinaryIO
from email.utils import parsedate_to_datetime
from datetime import datetime

# Import configuration
from config import (
    LOGGING, MAX_EMAIL_SIZE, MAX_ATTACHMENT_SIZE, ALLOWED_FILE_EXTENSIONS,
    CACHE_DIR, EMAIL_CACHE_DIR, THREAT_INTEL_CACHE
)

# Configure logging
logging.config.dictConfig(LOGGING)
logger = logging.getLogger("file_analyzer")

# Configuration
SUSPICIOUS_PATTERNS = ["password", "login", "credentials", "account"]  # Will be overridden by config
MALICIOUS_EXTENSIONS = ["exe", "js", "vbs", "wsf", "ps1", "psm1", "psd1", "ps1xml", "psc1", "msc", "jar", "jse", "job", "lnk", "pif", "scr", "hta", "com", "shb", "sct", "jsb", "wsc", "wsh", "msh", "msh1", "msh2", "mshxml", "msh1xml", "msh2xml", "scf", "url", "vb", "vbe", "vbs"]

# These will be updated from the config
MAX_FILE_SIZE_MB = MAX_ATTACHMENT_SIZE / (1024 * 1024)  # Convert bytes to MB
TRUSTED_MIME_TYPES = list(ALLOWED_FILE_EXTENSIONS)

class FileAnalyzer:
    def __init__(self):
        self.magic = None
        if MAGIC_AVAILABLE:
            try:
                self.magic = magic.Magic(mime=True)
            except Exception as e:
                logging.warning(f"Failed to initialize python-magic: {e}")
        self._init_file_signatures()
    
    def _init_file_signatures(self):
        """Initialize known file signatures (magic numbers)"""
        self.file_signatures = {
            b'\x25\x50\x44\x46': 'application/pdf',
            b'\x50\x4B\x03\x04': 'application/zip',  # Also used for docx, xlsx, etc.
            b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': 'application/ms-office',  # OLE2 Compound Document
            b'\x50\x4B\x05\x06': 'application/zip',  # Empty ZIP archive
            b'\x50\x4B\x07\x08': 'application/zip',  # Spanned ZIP archive
        }
        
    def _get_file_signature(self, file_data: bytes, length: int = 8) -> str:
        """Extract file signature (magic numbers) from file data"""
        if len(file_data) < length:
            return file_data.hex()
        return file_data[:length].hex()
    
    def _check_file_size(self, file_size: int) -> Tuple[bool, str]:
        """Check if file size is within allowed limits"""
        max_bytes = MAX_FILE_SIZE_MB * 1024 * 1024
        if file_size > max_bytes:
            return False, f"File size ({file_size/1024/1024:.2f}MB) exceeds maximum allowed size ({MAX_FILE_SIZE_MB}MB)"
        return True, ""
    
    def _check_file_extension(self, filename: str) -> Tuple[bool, str, str]:
        """Check file extension against known malicious extensions"""
        ext = os.path.splitext(filename)[1].lower().lstrip('.')
        if not ext:
            return True, "", ""
            
        if ext in MALICIOUS_EXTENSIONS:
            return False, ext, f"File has a potentially dangerous extension: .{ext}"
            
        # Check for double extensions
        parts = filename.split('.')
        if len(parts) > 2:  # Has multiple extensions
            if parts[-1].lower() in ['zip', 'rar', '7z'] and any(p.lower() in MALICIOUS_EXTENSIONS for p in parts[1:-1]):
                return False, ext, f"File has suspicious double extension with potentially dangerous format: .{'.'.join(parts[1:])}"
        
        return True, ext, ""
    
    def _check_file_signature(self, file_data: bytes, filename: str) -> Tuple[bool, str, str]:
        """Verify file signature matches its extension"""
        try:
            # Get MIME type from content
            mime_type = self._get_mime_type_from_signature(file_data)
            
            # Get expected MIME type from extension
            ext = os.path.splitext(filename)[1].lower().lstrip('.')
            expected_mime = self._get_expected_mime(ext)
            
            if not expected_mime:
                return True, mime_type, ""  # Unknown extension, can't verify
                
            # Check if the detected MIME type matches expected for the extension
            if mime_type and mime_type != expected_mime:
                return False, mime_type, f"File signature ({mime_type}) does not match file extension (.{ext} expected {expected_mime})"
                
            return True, mime_type, ""
        except Exception as e:
            logger.warning(f"Error checking file signature: {e}")
            return True, "unknown", ""  # Return true by default if we can't verify
    
    def _get_mime_type_from_signature(self, file_data: bytes) -> str:
        """Get MIME type from file signature (magic numbers)"""
        if not file_data:
            return ""
            
        # Check against known file signatures
        for signature, mime_type in self.file_signatures.items():
            if file_data.startswith(signature):
                return mime_type
                
        # Default to empty string if no match found
        return ""
        
    def _get_expected_mime(self, ext: str) -> str:
        """Get expected MIME type for a given file extension"""
        mime_map = {
            'pdf': 'application/pdf',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xls': 'application/vnd.ms-excel',
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'ppt': 'application/vnd.ms-powerpoint',
            'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'txt': 'text/plain',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'zip': 'application/zip',
            'rar': 'application/vnd.rar',
            '7z': 'application/x-7z-compressed',
        }
        return mime_map.get(ext.lower(), "")
    
    def _check_suspicious_content(self, file_data: bytes, filename: str) -> Tuple[bool, List[str]]:
        """Check file content for suspicious patterns"""
        warnings = []
        
        try:
            # Check for OLE objects in Office documents
            if filename.lower().endswith(('.doc', '.xls', '.ppt', '.docm', '.xlsm', '.pptm')):
                if self._contains_macros(file_data):
                    warnings.append("Document contains macros which could be malicious")
            
            # Check for JavaScript in PDFs
            if filename.lower().endswith('.pdf') and b'/JavaScript' in file_data[:4096]:
                warnings.append("PDF contains JavaScript which could be malicious")
            
            # Check for suspicious patterns in text-based files
            text_extensions = ['.txt', '.js', '.vbs', '.ps1', '.bat', '.cmd', '.wsf']
            if any(filename.lower().endswith(ext) for ext in text_extensions):
                try:
                    # Try to decode as text
                    try:
                        text = file_data.decode('utf-8', errors='replace')
                    except UnicodeDecodeError:
                        text = file_data.decode('latin-1', errors='replace')
                    
                    # Check for suspicious patterns
                    for pattern in SUSPICIOUS_PATTERNS:
                        if pattern and pattern in text.lower():
                            warnings.append(f"File contains suspicious pattern: {pattern}")
                            
                except Exception as e:
                    logger.debug(f"Error checking text content: {e}")
        
        except Exception as e:
            logger.warning(f"Error checking suspicious content: {e}")
            
        return len(warnings) == 0, warnings
    
    def _contains_macros(self, file_data: bytes) -> bool:
        """Check if Office document contains macros"""
        try:
            with olefile.OleFileIO(io.BytesIO(file_data)) as ole:
                return ole.exists('Macros') or ole.exists('_VBA_PROJECT')
        except Exception:
            return False
    
    def analyze_file(self, file_data: bytes, filename: str) -> Dict:
        """
        Analyze a file for potential security risks.
        
        Args:
            file_data: Binary content of the file
            filename: Original filename with extension
            
        Returns:
            Dict containing analysis results
        """
        result = {
            'filename': filename,
            'size_bytes': len(file_data),
            'is_safe': True,
            'warnings': [],
            'file_type': 'unknown',
            'verdict': 'clean',
            'details': {}
        }
        
        try:
            # Check file size
            size_ok, size_msg = self._check_file_size(len(file_data))
            if not size_ok:
                result['warnings'].append(size_msg)
                result['is_safe'] = False
                result['verdict'] = 'suspicious'
            
            # Check file extension
            ext_ok, ext, ext_msg = self._check_file_extension(filename)
            if not ext_ok:
                result['warnings'].append(ext_msg)
                result['is_safe'] = False
                result['verdict'] = 'malicious'
            result['file_extension'] = ext
            
            # Check file signature
            sig_ok, mime_type, sig_msg = self._check_file_signature(file_data, filename)
            if not sig_ok:
                result['warnings'].append(sig_msg)
                result['is_safe'] = False
                result['verdict'] = 'suspicious'
            result['mime_type'] = mime_type
            
            # Check for suspicious content
            content_ok, content_warnings = self._check_suspicious_content(file_data, filename)
            result['warnings'].extend(content_warnings)
            if not content_ok:
                result['is_safe'] = False
                if result['verdict'] != 'malicious':
                    result['verdict'] = 'suspicious'
            
            # Set file type based on MIME type
            result['file_type'] = mime_type.split('/')[0] if mime_type else 'unknown'
            
            # Update overall safety based on all checks
            if not result['is_safe']:
                if result['verdict'] == 'malicious':
                    result['risk_score'] = 100
                else:
                    result['risk_score'] = 70
            else:
                result['risk_score'] = 0
                
            # Add signature for further analysis
            result['signature'] = self._get_file_signature(file_data)
            
        except Exception as e:
            logger.error(f"Error analyzing file {filename}: {e}", exc_info=True)
            result['is_safe'] = False
            result['verdict'] = 'error'
            result['error'] = str(e)
            result['risk_score'] = 50  # Unknown risk
            
        return result

# Singleton instance
file_analyzer = FileAnalyzer()

def analyze_attachments(attachments: List[Dict]) -> Dict:
    """
    Analyze a list of email attachments for potential security risks.
    
    Args:
        attachments: List of attachment dicts with 'filename' and 'data' keys
        
    Returns:
        Dict containing overall analysis and per-file results
    """
    if not attachments:
        return {
            'has_attachments': False,
            'has_malicious': False,
            'has_suspicious': False,
            'files': [],
            'risk_score': 0,
            'warnings': []
        }
    
    results = []
    has_malicious = False
    has_suspicious = False
    warnings = []
    
    for attachment in attachments:
        if 'data' not in attachment or not attachment['data']:
            continue
            
        filename = attachment.get('filename', 'unnamed')
        try:
            file_result = file_analyzer.analyze_file(attachment['data'], filename)
            results.append(file_result)
            
            if not file_result['is_safe']:
                if file_result['verdict'] == 'malicious':
                    has_malicious = True
                else:
                    has_suspicious = True
                    
            warnings.extend(file_result.get('warnings', []))
            
        except Exception as e:
            logger.error(f"Error processing attachment {filename}: {e}", exc_info=True)
            results.append({
                'filename': filename,
                'error': str(e),
                'is_safe': False,
                'verdict': 'error',
                'risk_score': 50
            })
            warnings.append(f"Error processing {filename}: {str(e)}")
    
    # Calculate overall risk score (max of all file scores)
    risk_score = max([f.get('risk_score', 0) for f in results], default=0)
    
    return {
        'has_attachments': len(results) > 0,
        'has_malicious': has_malicious,
        'has_suspicious': has_suspicious,
        'files': results,
        'risk_score': risk_score,
        'warnings': warnings
    }

def is_file_type_allowed(file_data: bytes, filename: str) -> bool:
    """
    Check if a file is of an allowed type based on its content and extension.
    
    Args:
        file_data: Binary content of the file
        filename: Original filename with extension
        
    Returns:
        bool: True if the file type is allowed, False otherwise
    """
    try:
        # Get MIME type from content
        mime_type = file_analyzer.magic.from_buffer(file_data[:1024])
        
        # Check against trusted MIME types
        if mime_type.lower() in TRUSTED_MIME_TYPES:
            return True
            
        # Additional checks for specific file types
        if mime_type.startswith('text/'):
            return True
            
        # Check file extension against MIME type
        ext = os.path.splitext(filename)[1].lower().lstrip('.')
        if not ext:
            return False
            
        expected_mime = file_analyzer._get_expected_mime(ext)
        if expected_mime and mime_type == expected_mime:
            return True
            
        return False
        
    except Exception as e:
        logger.warning(f"Error checking file type: {e}")
        return False
