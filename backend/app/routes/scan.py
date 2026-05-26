"""TraceZ Backend — Scanning Router."""

import json
import time
from urllib.parse import urlparse
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db, ScanLog, BlocklistEntry, User
from app.utils.validators import validate_url_ssrf_safe
from app.utils.sanitizer import clean_url
from app.middleware.auth import get_current_user
from app.services.url_analyzer import unroll_redirects_safe
from app.services.phishing_detector import analyze_heuristics
from app.services.reputation import get_reputation_summary
from app.services.verdict import calculate_verdict

router = APIRouter(prefix="/api/scan", tags=["Scanning"])

# Load allowlist from shared folder once
SAFE_DOMAINS = set()
try:
    _allowlist_path = Path(__file__).resolve().parent.parent.parent.parent / "shared" / "blocklists" / "safe-domains.json"
    if _allowlist_path.exists():
        with open(_allowlist_path, "r", encoding="utf-8") as f:
            _data = json.load(f)
            SAFE_DOMAINS = {domain.lower() for domain in _data.get("domains", [])}
except Exception as e:
    print(f"[!] Error loading safe allowlist: {e}")

# --- Request / Response Schemas ---

class ScanRequest(BaseModel):
    url: str

# --- Endpoints ---

@router.get("/history")
def get_public_scan_history(
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Retrieve the recent scan history for public dashboard."""
    logs = db.query(ScanLog).order_by(ScanLog.created_at.desc()).limit(limit).all()
    results = []
    for log in logs:
        results.append({
            "id": log.id,
            "url": log.url,
            "verdict": log.verdict,
            "risk_score": log.risk_score,
            "scan_time_ms": log.scan_time_ms,
            "created_at": log.created_at.isoformat() if log.created_at else None,
            "signals": log.signals,
            "reputation": log.reputation
        })
    return results

@router.post("/url")
async def scan_url(
    payload: ScanRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Perform a complete multi-layered security scan on a URL.
    This follows redirects, evaluates heuristics, queries reputation systems,
    and returns a structured security verdict.
    """
    start_time = time.time()
    url = clean_url(payload.url)
    
    # 1. Syntactic & basic SSRF validation
    is_safe, error_msg = validate_url_ssrf_safe(url)
    dns_failed = False
    if not is_safe:
        if error_msg == "Could not resolve hostname DNS.":
            dns_failed = True
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"URL is invalid or prohibited by security policy: {error_msg}"
            )
        
    # 2. Extract initial domain and check allowlist
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    if ":" in domain:
        domain = domain.split(":")[0]
    domain_lower = domain.lower()
    
    # If on safe domains allowlist, bypass downstream scans
    if domain_lower in SAFE_DOMAINS:
        result = {
            "url": url,
            "verdict": "SAFE",
            "risk_score": 0,
            "scan_time_ms": int((time.time() - start_time) * 1000),
            "signals": [{"layer": "allowlist", "signal": "Domain is on trusted allowlist", "score": 0}],
            "reputation": {"google_safe_browsing": "clean", "virustotal": {"malicious": 0}, "otx": {"pulse_count": 0}},
            "recommendation": "This site is on the safe allowlist.",
            "cached": False
        }
        # Log safe scan
        log_scan(db, url, "SAFE", 0, result["signals"], result["reputation"], current_user.id if current_user else None)
        return result

    # 3. Unroll redirects safely
    if dns_failed:
        chain = [url]
        is_down = True
        final_url = url
        final_domain_lower = domain_lower
    else:
        chain, is_down = await unroll_redirects_safe(url)
        final_url = chain[-1]
        
        final_parsed = urlparse(final_url)
        final_domain = final_parsed.netloc or final_parsed.path.split("/")[0]
        if ":" in final_domain:
            final_domain = final_domain.split(":")[0]
        final_domain_lower = final_domain.lower()
    
    # 4. Check if final domain is on blocklist in DB
    on_blocklist = db.query(BlocklistEntry).filter(BlocklistEntry.domain == final_domain_lower).first() is not None
    
    # 5. Gather heuristics
    signals = analyze_heuristics(final_url, final_domain_lower)
    if is_down:
        signals.append({
            "layer": "domain",
            "signal": "Website is offline/unreachable",
            "score": 20,
            "confidence": 1.0
        })
        
    # 6. Query threat reputation APIs
    reputation = await get_reputation_summary(final_url, final_domain_lower)
    
    # 7. Evaluate verdict
    verdict_outcome = calculate_verdict(final_url, final_domain_lower, signals, reputation, on_blocklist)
    
    # Compile complete response
    scan_time_ms = int((time.time() - start_time) * 1000)
    response_data = {
        "url": url,
        "final_url": final_url,
        "redirect_chain": chain,
        "verdict": verdict_outcome["verdict"],
        "risk_score": verdict_outcome["risk_score"],
        "scan_time_ms": scan_time_ms,
        "signals": signals,
        "reputation": reputation,
        "recommendation": verdict_outcome["recommendation"],
        "cached": False
    }
    
    # Log the scan outcome
    log_scan(
        db=db,
        url=url,
        verdict=verdict_outcome["verdict"],
        risk_score=verdict_outcome["risk_score"],
        signals=signals,
        reputation=reputation,
        user_id=current_user.id if current_user else None
    )
    
    return response_data

@router.post("/url/quick")
def scan_url_quick(payload: ScanRequest, db: Session = Depends(get_db)):
    """
    Perform a fast local-only scan without unrolling redirects or checking external APIs.
    Used for extension badge display and quick client reviews.
    """
    url = clean_url(payload.url)
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    if ":" in domain:
        domain = domain.split(":")[0]
    domain_lower = domain.lower()
    
    # Allowlist check
    if domain_lower in SAFE_DOMAINS:
        return {
            "url": url,
            "verdict": "SAFE",
            "risk_score": 0,
            "recommendation": "Safe allowlisted domain."
        }
        
    # Blocklist check
    on_blocklist = db.query(BlocklistEntry).filter(BlocklistEntry.domain == domain_lower).first() is not None
    
    # Heuristics
    signals = analyze_heuristics(url, domain_lower)
    
    # Simplified verdict calculations
    score = 95 if on_blocklist else min(75, sum(s.get("score", 0) for s in signals))
    
    if score >= 70:
        verdict = "DANGEROUS"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
        
    return {
        "url": url,
        "verdict": verdict,
        "risk_score": score,
        "on_blocklist": on_blocklist,
        "signals_count": len(signals)
    }

class ExtensionScanLogRequest(BaseModel):
    url: str
    verdict: str
    risk_score: int
    signals: Optional[list] = []
    reputation: Optional[dict] = {}

@router.post("/log")
def log_extension_scan(
    payload: ExtensionScanLogRequest,
    db: Session = Depends(get_db)
):
    """Write log generated locally by browser extension."""
    log_scan(
        db=db,
        url=payload.url,
        verdict=payload.verdict,
        risk_score=payload.risk_score,
        signals=payload.signals or [],
        reputation=payload.reputation or {},
        user_id=None
    )
    return {"status": "success"}

# --- Helper function ---

def log_scan(db: Session, url: str, verdict: str, risk_score: int, signals: list, reputation: dict, user_id: Optional[int]):
    """Write scan logs to database."""
    try:
        log = ScanLog(
            url=url,
            verdict=verdict,
            risk_score=risk_score,
            user_id=user_id
        )
        log.signals = signals
        log.reputation = reputation
        
        db.add(log)
        db.commit()
    except Exception as e:
        print(f"[!] Error writing scan log to DB: {e}")
        db.rollback()
