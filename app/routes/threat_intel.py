"""TraceZ Backend — Threat Intelligence and Blocklist Sync Router."""

from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db, BlocklistEntry, User, AuditLog
from app.middleware.auth import get_current_user, api_key_header
from app.services.threat_intel import get_blocklist_version_hash, compile_blocklist_json

router = APIRouter(tags=["Threat Intelligence"])

# --- Request Schemas ---
class ReportRequest(BaseModel):
    url: str
    category: str  # "false_positive" or "false_negative"
    comments: str

# --- Endpoints ---

@router.get("/api/blocklist/version")
def check_blocklist_version(
    db: Session = Depends(get_db)
):
    """Retrieve the current active blocklist version hash."""
    version_hash = get_blocklist_version_hash(db)
    return {
        "version": version_hash,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@router.get("/api/blocklist/download")
def download_blocklist(
    db: Session = Depends(get_db)
):
    """Download the complete blocklist package containing all malicious domains."""
    blocklist_pkg = compile_blocklist_json(db)
    return blocklist_pkg

from fastapi import Request

@router.post("/api/report", status_code=status.HTTP_201_CREATED)
def report_url(
    payload: ReportRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Submit a threat feedback report (false positive or false negative)."""
    user_id = None
    try:
        if "tracez_session" in request.cookies or "Authorization" in request.headers or "X-TraceZ-API-Key" in request.headers:
            user = get_current_user(request, db)
            user_id = user.id
    except Exception:
        pass

    audit = AuditLog(
        user_id=user_id,
        action="user_threat_report",
        ip_address=request.client.host if request.client else None,
        details=f"Reported URL: {payload.url} | Category: {payload.category} | Comment: {payload.comments}"
    )
    db.add(audit)
    db.commit()
    
    return {"message": "Thank you for your report. Our security team will review it shortly."}

class BlocklistToggleRequest(BaseModel):
    domain: str
    category: str = "phishing"

@router.post("/api/blocklist/add")
def add_to_blocklist_public(
    payload: BlocklistToggleRequest,
    db: Session = Depends(get_db)
):
    """Add a domain to the blocklist anonymously from dashboard control."""
    domain_lower = payload.domain.strip().lower()
    existing = db.query(BlocklistEntry).filter(BlocklistEntry.domain == domain_lower).first()
    if not existing:
        entry = BlocklistEntry(domain=domain_lower, category=payload.category, source="user_public")
        db.add(entry)
        db.commit()
    return {"status": "success", "message": f"Added {domain_lower} to blocklist."}

@router.post("/api/blocklist/remove")
def remove_from_blocklist_public(
    payload: BlocklistToggleRequest,
    db: Session = Depends(get_db)
):
    """Remove a domain from the blocklist (Allow it) anonymously from dashboard control."""
    domain_lower = payload.domain.strip().lower()
    entry = db.query(BlocklistEntry).filter(BlocklistEntry.domain == domain_lower).first()
    if entry:
        db.delete(entry)
        db.commit()
    return {"status": "success", "message": f"Removed {domain_lower} from blocklist."}
