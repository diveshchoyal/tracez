"""TraceZ Backend — Reputation API Integration (VirusTotal, Safe Browsing, OTX)."""

import hashlib
import httpx
from typing import Dict
from app.config import settings

async def check_virustotal(url: str) -> Dict:
    """Query VirusTotal API v3 for URL reputation. Falls back to mock if no API key."""
    if not settings.VIRUSTOTAL_API_KEY:
        # Mock Response based on url features for reproducibility
        is_suspicious = "prize" in url or "verify" in url or "fitgirl" in url
        return {
            "malicious": 5 if is_suspicious else 0,
            "suspicious": 1 if is_suspicious else 0,
            "harmless": 60,
            "undetected": 10
        }
        
    # Standard VT API call
    url_id = hashlib.sha256(url.encode()).hexdigest()
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    
    async with httpx.AsyncClient(timeout=3.0) as client:
        try:
            resp = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
            if resp.status_code == 200:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                }
        except Exception:
            pass
            
    return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}

async def check_google_safe_browsing(url: str) -> str:
    """Query Google Safe Browsing Lookup API. Returns 'phishing', 'malware', or 'clean'."""
    if not settings.GOOGLE_SAFE_BROWSING_KEY:
        # Mock Response
        if "login-microsoftonline.tk" in url or "secure-paypal-verify.ml" in url:
            return "phishing"
        return "clean"
        
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_KEY}"
    payload = {
        "client": {"clientId": "tracez-extension", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    async with httpx.AsyncClient(timeout=3.0) as client:
        try:
            resp = await client.post(api_url, json=payload)
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                if matches:
                    threat_type = matches[0].get("threatType")
                    if threat_type == "SOCIAL_ENGINEERING":
                        return "phishing"
                    return "malware"
        except Exception:
            pass
            
    return "clean"

async def check_otx_alienvault(domain: str) -> Dict:
    """Query AlienVault OTX for domain reputation."""
    if not settings.OTX_API_KEY:
        # Mock Response
        return {"pulse_count": 0, "is_malicious": False}
        
    headers = {"X-OTX-API-KEY": settings.OTX_API_KEY}
    api_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    
    async with httpx.AsyncClient(timeout=3.0) as client:
        try:
            resp = await client.get(api_url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                # If there are multiple active threat pulses, flag it
                return {
                    "pulse_count": pulse_count,
                    "is_malicious": pulse_count > 3
                }
        except Exception:
            pass
            
    return {"pulse_count": 0, "is_malicious": False}

async def get_reputation_summary(url: str, domain: str) -> Dict:
    """Consolidate external reputation check results."""
    vt = await check_virustotal(url)
    gsb = await check_google_safe_browsing(url)
    otx = await check_otx_alienvault(domain)
    
    return {
        "virustotal": vt,
        "google_safe_browsing": gsb,
        "otx": otx
    }
