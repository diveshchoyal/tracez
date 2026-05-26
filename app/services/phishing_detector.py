"""TraceZ Backend — Phishing Heuristics and Typosquat Detection Service."""

import re
from typing import Dict, List, Optional, Tuple

TOP_BRANDS = [
    "google.com", "facebook.com", "amazon.com", "netflix.com", "paypal.com",
    "microsoft.com", "apple.com", "twitter.com", "github.com", "instagram.com",
    "linkedin.com", "zoom.us", "dropbox.com", "chase.com", "bankofamerica.com",
    "fitgirl-repacks.site"
]

SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "signin", "update", "billing", "account", "bank", "portal"]
FREE_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz"}

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the edit distance between two strings."""
    if len(s1) > len(s2):
        s1, s2 = s2, s1
    distances = range(len(s1) + 1)
    for i2, c2 in enumerate(s2):
        distances_ = [i2+1]
        for i1, c1 in enumerate(s1):
            if c1 == c2:
                distances_.append(distances[i1])
            else:
                distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
        distances = distances_
    return distances[-1]

def check_homoglyph(domain: str) -> Tuple[bool, Optional[str]]:
    """
    Check if a domain is a homoglyph attack.
    Detects if the domain starts with punycode (xn--) or contains mixed non-ASCII scripts.
    """
    domain = domain.lower()
    
    # Check for Punycode
    if domain.startswith("xn--"):
        try:
            # Decode Punycode to get Unicode representation
            decoded = domain.encode("ascii").decode("idna")
            return True, f"Punycode domain resolves to Unicode: {decoded}"
        except Exception:
            return True, "Obfuscated/invalid Punycode domain"
            
    # Check if any character is non-ASCII
    if any(ord(char) > 127 for char in domain):
        return True, "Contains Unicode confusable characters"
        
    return False, None

def check_typosquat(domain: str) -> Dict:
    """
    Check if a domain is typo-squatting a major brand.
    Returns info dict if it's suspicious.
    """
    clean_domain = domain.lower()
    if clean_domain.startswith("www."):
        clean_domain = clean_domain[4:]
        
    # FitGirl-repacks specific check (Requirement 3/4)
    if "fitgirl" in clean_domain:
        if clean_domain != "fitgirl-repacks.site":
            return {
                "typosquat": True,
                "target_brand": "fitgirl-repacks.site",
                "distance": 1,
                "is_malicious_clone": True,
                "message": "Domain is an unofficial/malicious clone of FitGirl Repacks"
            }
            
    for brand in TOP_BRANDS:
        # Exact match check
        if clean_domain == brand:
            continue
            
        # Check edit distance
        dist = levenshtein_distance(clean_domain, brand)
        if dist in (1, 2):
            return {
                "typosquat": True,
                "target_brand": brand,
                "distance": dist,
                "is_malicious_clone": False,
                "message": f"Domain mimics official brand: {brand} (distance: {dist})"
            }
            
        # Check brand name as subdomain or prefix (e.g., login-paypal.com)
        brand_name = brand.split(".")[0]
        if brand_name in clean_domain:
            return {
                "typosquat": True,
                "target_brand": brand,
                "distance": 0,
                "is_malicious_clone": False,
                "message": f"Domain contains target brand name: {brand_name}"
            }
            
    return {"typosquat": False}

def analyze_heuristics(url: str, domain: str) -> List[Dict]:
    """
    Analyze url & domain heuristics and return found signals with risk scores.
    """
    signals = []
    clean_domain = domain.lower()
    
    # 1. IP Address check
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, clean_domain) or ":" in clean_domain and clean_domain.count(":") > 1:
        signals.append({
            "layer": "domain",
            "signal": "IP address used instead of domain name",
            "score": 20,
            "confidence": 1.0
        })
        
    # 2. Free / Suspicious TLD
    for tld in FREE_TLDS:
        if clean_domain.endswith(tld):
            signals.append({
                "layer": "domain",
                "signal": f"Suspicious free TLD ({tld})",
                "score": 10,
                "confidence": 1.0
            })
            break
            
    # 3. Excessive subdomain count
    # Split by '.' and count parts
    subdomains = clean_domain.split(".")
    # Remove TLD and SLD
    if len(subdomains) > 4:
        signals.append({
            "layer": "domain",
            "signal": "Excessive subdomain nesting depth",
            "score": 10,
            "confidence": 0.8
        })
        
    # 4. Homoglyphs
    is_homoglyph, h_msg = check_homoglyph(clean_domain)
    if is_homoglyph:
        signals.append({
            "layer": "homoglyph",
            "signal": h_msg,
            "score": 40,
            "confidence": 0.95
        })
        
    # 5. Typosquatting
    typosquat_info = check_typosquat(clean_domain)
    if typosquat_info.get("typosquat"):
        score = 50 if typosquat_info.get("is_malicious_clone") else 25
        signals.append({
            "layer": "homoglyph",
            "signal": typosquat_info["message"],
            "score": score,
            "confidence": 0.95
        })
        
    # 6. Suspicious path components
    path = url.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        # Only flag keywords in path if it's not a top-tier brand
        if f"/{kw}" in path and clean_domain not in TOP_BRANDS:
            signals.append({
                "layer": "url_pattern",
                "signal": f"URL path contains sensitive keyword: '{kw}'",
                "score": 15,
                "confidence": 0.75
            })
            break
            
    # 7. Redirection/At Symbol trick
    if "@" in url:
        signals.append({
            "layer": "url_pattern",
            "signal": "URL contains '@' symbol (often used for redirection obfuscation)",
            "score": 20,
            "confidence": 0.9
        })
        
    return signals
