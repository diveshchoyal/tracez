"""TraceZ Backend — Validation Utilities (including SSRF Protection)."""

import ipaddress
import re
import socket
from urllib.parse import urlparse
from typing import Tuple, Optional

# Regex for basic validation of email
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

def validate_email(email: str) -> bool:
    """Check if the email format is valid."""
    return bool(EMAIL_REGEX.match(email))

def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """Validate password strength. Minimum 8 characters, at least one letter and one number."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(c.isalpha() for c in password):
        return False, "Password must contain at least one letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."
    return True, None

def is_ssrf_safe_ip(ip_str: str) -> bool:
    """
    Check if an IP address is safe to query (not private, loopback, multicast, or link-local).
    This prevents Server-Side Request Forgery (SSRF) attacks.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        
        # Check if the IP falls in any restricted ranges
        if ip.is_private:  # RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            return False
        if ip.is_loopback:  # 127.0.0.0/8, ::1
            return False
        if ip.is_link_local:  # 169.254.0.0/16, fe80::/10
            return False
        if ip.is_multicast:  # 224.0.0.0/4, ff00::/8
            return False
        if ip.is_reserved:  # Reserved IPs
            return False
        if ip.is_unspecified:  # 0.0.0.0, ::
            return False
            
        return True
    except ValueError:
        return False

def validate_url_ssrf_safe(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a URL to ensure it is syntactically correct and SSRF-safe.
    Resolves DNS and verifies the resolved IPs are not in restricted ranges.
    Returns (is_safe, error_message).
    """
    try:
        parsed = urlparse(url)
        if not parsed.scheme or parsed.scheme not in ("http", "https"):
            return False, "Invalid scheme. Only HTTP and HTTPS are allowed."
            
        hostname = parsed.hostname
        if not hostname:
            return False, "Missing hostname in URL."
            
        # Check for obvious local hosts in hostname
        if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return False, "Access to localhost or local addresses is prohibited."
            
        # Resolve all IP addresses for the hostname
        try:
            # getaddrinfo works for both IPv4 and IPv6
            addr_info = socket.getaddrinfo(hostname, parsed.port or (80 if parsed.scheme == "http" else 443))
        except socket.gaierror:
            # If DNS resolution fails, the URL might still be safe (or just unreachable).
            # However, for an active scanning tool, we cannot scan if DNS resolution fails.
            return False, "Could not resolve hostname DNS."
            
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip = sockaddr[0]
            if not is_ssrf_safe_ip(ip):
                return False, f"URL resolves to a restricted/private IP address: {ip}."
                
        return True, None
    except Exception as e:
        return False, f"URL validation failed: {str(e)}"
