"""
Attachment Preview Module - PDF-style viewer for text files and documents
Handles text files, DOC/DOCX files with PDF-like interface
"""

import os
import base64
import mimetypes
import html
import logging
from flask import make_response

logger = logging.getLogger("attachment_preview")

# Text file extensions that should use the PDF viewer
TEXT_EXTENSIONS = [
    '.txt', '.log', '.csv', '.json', '.xml', '.html', '.htm', 
    '.css', '.js', '.py', '.md', '.yaml', '.yml', '.ini', 
    '.cfg', '.conf', '.sh', '.bat', '.sql', '.php', '.rb', 
    '.go', '.java', '.cpp', '.c', '.h', '.hpp', '.rs', 
    '.swift', '.kt', '.scala', '.r', '.m', '.pl', '.lua'
]

# Office document MIME types
OFFICE_MIME_TYPES = [
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/msword',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation'
]

def detect_mime_type(data, filename):
    """Detect MIME type from file signature and filename"""
    # Start with filename-based detection
    mime, _ = mimetypes.guess_type(filename)
    
    # If no MIME from filename, try file signature
    if not mime or mime == "application/octet-stream":
        sig = data[:16]
        if sig.startswith(b"%PDF"):
            mime = "application/pdf"
        elif sig.startswith(b"\xFF\xD8"):
            mime = "image/jpeg"
        elif sig.startswith(b"\x89PNG"):
            mime = "image/png"
        elif sig.startswith(b"GIF8"):
            mime = "image/gif"
        elif sig[:4] == b"RIFF" and b"AVI" in sig:
            mime = "video/avi"
        elif sig[:4] == b"RIFF" and b"WAVE" in sig:
            mime = "audio/wav"
        elif sig[:3] == b"ID3" or sig[0:2] == b"\xFF\xFB":
            mime = "audio/mpeg"
        elif sig[:4] == b"\x00\x00\x00\x18" or sig[4:8] == b"ftyp":
            mime = "video/mp4"
        else:
            # Check if it's text-like
            try:
                sample = data[:4000].decode("utf-8")
                mime = "text/plain"
            except Exception:
                # Check text file extensions
                if any(filename.lower().endswith(ext) for ext in TEXT_EXTENSIONS):
                    mime = "text/plain"
                else:
                    mime = "application/octet-stream"
    
    return mime

def extract_text_from_docx(data):
    """Extract text from DOCX file"""
    try:
        import io
        from docx import Document
        
        doc = Document(io.BytesIO(data))
        text_content = []
        
        for paragraph in doc.paragraphs:
            text_content.append(paragraph.text)
        
        return '\n'.join(text_content)
    except ImportError:
        logger.warning("python-docx not installed, cannot extract text from DOCX")
        return None
    except Exception as e:
        logger.error(f"Error extracting text from DOCX: {e}")
        return None

def extract_text_from_doc(data):
    """Extract text from legacy DOC file"""
    try:
        import textract
        import io
        
        text = textract.process(io.BytesIO(data)).decode('utf-8')
        return text
    except ImportError:
        logger.warning("textract not installed, cannot extract text from DOC")
        return None
    except Exception as e:
        logger.error(f"Error extracting text from DOC: {e}")
        return None

def get_syntax_highlighter_class(filename):
    """Get CSS class for syntax highlighting based on file extension"""
    ext = os.path.splitext(filename)[1].lower()
    
    syntax_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.html': 'html',
        '.htm': 'html',
        '.css': 'css',
        '.json': 'json',
        '.xml': 'xml',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.sql': 'sql',
        '.php': 'php',
        '.java': 'java',
        '.cpp': 'cpp',
        '.c': 'c',
        '.h': 'c',
        '.hpp': 'cpp',
        '.rs': 'rust',
        '.go': 'go',
        '.rb': 'ruby',
        '.swift': 'swift',
        '.kt': 'kotlin',
        '.scala': 'scala',
        '.sh': 'bash',
        '.bat': 'batch',
        '.pl': 'perl',
        '.lua': 'lua'
    }
    
    return syntax_map.get(ext, 'text')

def paginate_text(text, lines_per_page=50):
    """Split text into pages"""
    lines = text.split('\n')
    pages = []
    
    for i in range(0, len(lines), lines_per_page):
        page_lines = lines[i:i + lines_per_page]
        pages.append('\n'.join(page_lines))
    
    return pages

def text_file_viewer(content, filename, pages=None):
    """Generate PDF-style viewer HTML"""
    # Escape content for HTML
    escaped_content = html.escape(content)
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{html.escape(filename)}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: white;
            padding: 15px;
            border-bottom: 1px solid #ddd;
            margin-bottom: 20px;
            border-radius: 4px;
        }}
        .filename {{
            font-size: 18px;
            font-weight: bold;
            color: #333;
        }}
        .content {{
            background: white;
            padding: 20px;
            border-radius: 4px;
            white-space: pre-wrap;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.4;
            overflow: auto;
            max-height: 80vh;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="filename">{html.escape(filename)}</div>
    </div>
    <div class="content">{escaped_content}</div>
</body>
</html>"""
    
    return html_content

def handle_text_files(data, filename):
    """Handle text files with PDF-style viewer"""
    try:
        text_content = data.decode('utf-8')
        
        # Limit text size for preview (max 1MB)
        if len(text_content) > 1000000:
            text_content = text_content[:1000000] + "\n\n... [Content truncated for preview] ..."
        
        # Generate PDF-style HTML
        html_content = text_file_viewer(text_content, filename)
        
        resp = make_response(html_content)
        resp.headers["Content-Type"] = "text/html"
        resp.headers["Content-Disposition"] = f'inline; filename="{os.path.splitext(filename)[0]}.html"'
        resp.headers["Cache-Control"] = "no-store"
        return resp
        
    except UnicodeDecodeError:
        return None

def handle_doc_files(data, filename):
    """Handle DOC/DOCX files by extracting text and using PDF viewer"""
    filename_lower = filename.lower()
    
    if filename_lower.endswith('.docx'):
        text_content = extract_text_from_docx(data)
    elif filename_lower.endswith('.doc'):
        text_content = extract_text_from_doc(data)
    else:
        return None
    
    if text_content:
        # Limit text size
        if len(text_content) > 1000000:
            text_content = text_content[:1000000] + "\n\n... [Content truncated for preview] ..."
        
        # Generate PDF-style HTML
        html_content = text_file_viewer(text_content, filename)
        
        resp = make_response(html_content)
        resp.headers["Content-Type"] = "text/html"
        resp.headers["Content-Disposition"] = f'inline; filename="{os.path.splitext(filename)[0]}.html"'
        resp.headers["Cache-Control"] = "no-store"
        return resp
    
    # Return error message if extraction failed
    error_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Preview Not Available</title>
    <style>
        body {{ 
            font-family: Arial, sans-serif; 
            text-align: center; 
            padding: 50px; 
            background: #f5f5f5; 
        }}
        .message {{ 
            background: white; 
            padding: 30px; 
            border-radius: 10px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
            max-width: 500px; 
            margin: 0 auto; 
        }}
    </style>
</head>
<body>
    <div class="message">
        <h3>Document Preview Not Available</h3>
        <p>Could not extract text from {html.escape(filename)}.</p>
        <p>Please use the Download button to view this file.</p>
    </div>
</body>
</html>"""
    
    resp = make_response(error_html)
    resp.headers["Content-Type"] = "text/html"
    resp.headers["Cache-Control"] = "no-store"
    return resp

def preview_attachment(msg_id, attachment_id, gmail_utils, email_cache):
    """
    Robust inline preview handler for Gmail attachments.
    Features PDF-style viewer for text files and documents.
    """
    try:
        service = gmail_utils.get_service()
        if not service:
            return "Gmail service unavailable", 500

        # --- locate metadata ---
        item = email_cache.get_cached_email(msg_id)
        att_meta = None
        if item and item.get("attachments"):
            for a in item["attachments"]:
                if a.get("attachmentId") == attachment_id:
                    att_meta = a
                    break

        # --- fetch raw Gmail data ---
        data = gmail_utils.get_attachment_data(service, "me", msg_id, attachment_id)
        if not data:
            logger.warning(f"[ATTACH-PREV] No data for msg={msg_id} att={attachment_id}")
            return "Attachment not found", 404

        # Gmail sometimes returns str → base64 decode
        if isinstance(data, str):
            try:
                data = base64.urlsafe_b64decode(data)
            except Exception:
                logger.warning(f"[ATTACH-PREV] Base64 decode failed for {attachment_id}")
                return "Failed to decode attachment", 415

        # --- MIME detection ---
        filename = att_meta.get("filename") if att_meta else f"{attachment_id}.bin"
        mime = detect_mime_type(data, filename)

        # --- handle text files with PDF viewer ---
        if mime.startswith("text/") or any(filename.lower().endswith(ext) for ext in TEXT_EXTENSIONS):
            resp = handle_text_files(data, filename)
            if resp:
                return resp

        # --- handle DOC/DOCX files ---
        if any(filename.lower().endswith(ext) for ext in ['.doc', '.docx']):
            resp = handle_doc_files(data, filename)
            if resp:
                return resp

        # --- handle office docs (other than DOC/DOCX) ---
        if any(mime.startswith(t) for t in OFFICE_MIME_TYPES):
            error_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Preview Not Available</title>
    <style>
        body {{ 
            font-family: Arial, sans-serif; 
            text-align: center; 
            padding: 50px; 
            background: #f5f5f5; 
        }}
        .message {{ 
            background: white; 
            padding: 30px; 
            border-radius: 10px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
            max-width: 500px; 
            margin: 0 auto; 
        }}
    </style>
</head>
<body>
    <div class="message">
        <h3>Preview Not Available</h3>
        <p>This file type ({html.escape(filename)}) cannot be previewed directly.</p>
        <p>Please use the Download button to view this file.</p>
    </div>
</body>
</html>"""
            
            resp = make_response(error_html)
            resp.headers["Content-Type"] = "text/html"
            resp.headers["Cache-Control"] = "no-store"
            return resp

        # --- allow inline types ---
        inline_ok = (
            mime.startswith("image/") or
            mime.startswith("video/") or
            mime.startswith("audio/") or
            mime == "application/pdf"
        )

        if not inline_ok:
            return "Preview not supported for this type", 415

        # --- return inline for other types ---
        from flask import Flask
        resp = make_response(data)
        resp.headers["Content-Type"] = mime
        resp.headers["Content-Disposition"] = f'inline; filename="{filename}"'
        resp.headers["Cache-Control"] = "no-store"

        return resp

    except Exception as e:
        logger.exception(f"[ATTACH-PREV] Error in preview_attachment: {e}")
        return f"Preview error: {str(e)}", 500