"""TraceZ Backend — Input Sanitization Utilities."""

import html
import re
from pathlib import Path

def sanitize_html(text: str) -> str:
    """Escape HTML special characters to prevent cross-site scripting (XSS)."""
    if not text:
        return ""
    return html.escape(text)

def sanitize_email(email: str) -> str:
    """Normalize and sanitize an email address."""
    if not email:
        return ""
    # Lowercase, strip whitespace, keep only valid email chars
    email = email.strip().lower()
    return re.sub(r"[^\w\.\@\-\+]", "", email)

def sanitize_filename(filename: str) -> str:
    """Sanitize filenames to prevent path traversal (e.g. '../../etc/passwd')."""
    if not filename:
        return "unnamed_file"
    
    # Get only the basename
    name = Path(filename).name
    
    # Replace anything that isn't alphanumeric, underscore, hyphen, or dot
    name = re.sub(r"[^\w\.\-]", "_", name)
    
    # Remove leading dots or multiple dots to prevent traversal/obfuscation
    name = re.sub(r"\.+", ".", name)
    if name.startswith("."):
        name = "safe_" + name.lstrip(".")
        
    return name or "safe_filename"

def clean_url(url: str) -> str:
    """Remove fragment identifiers and strip spaces from URLs."""
    if not url:
        return ""
    url = url.strip()
    # Remove fragment (after #) as it isn't sent to server in HTTP requests anyway, 
    # but might be present in URL scan payload
    if "#" in url:
        url = url.split("#")[0]
    return url
