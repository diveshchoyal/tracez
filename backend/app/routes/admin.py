"""TraceZ Backend — Admin Dashboard Router."""

from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db, User, ScanLog, BlocklistEntry, AuditLog, ThreatFeed
from app.middleware.auth import get_current_admin
from app.services.threat_intel import fetch_and_sync_feeds

router = APIRouter(prefix="/api/admin", tags=["Admin Dashboard"])

# --- Request / Response Schemas ---

class BlocklistCreate(BaseModel):
    domain: str
    category: str = "phishing"
    source: str = "custom"

class BlocklistEntryResponse(BaseModel):
    id: int
    domain: str
    category: str
    source: str
    created_at: datetime

    class Config:
        from_attributes = True

# --- Endpoints ---

@router.get("/metrics")
def get_metrics(
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    """Retrieve system-wide analytics and performance counters."""
    total_users = db.query(User).count()
    total_scans = db.query(ScanLog).count()
    total_threat_domains = db.query(BlocklistEntry).count()
    
    # Count of flagged scans (verdicts: SUSPICIOUS and DANGEROUS)
    flagged_scans = db.query(ScanLog).filter(ScanLog.verdict.in_(["SUSPICIOUS", "DANGEROUS"])).count()
    
    # Recent threat feeds
    feeds = db.query(ThreatFeed).all()
    feed_summary = [{"name": f.name, "status": f.last_sync_status, "time": f.last_sync_time} for f in feeds]
    
    return {
        "users_count": total_users,
        "scans_count": total_scans,
        "threat_domains_count": total_threat_domains,
        "flagged_scans_count": flagged_scans,
        "feeds": feed_summary
    }

@router.get("/scans")
def get_scan_history(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    """Retrieve paginated log of all URL and file scans."""
    logs = db.query(ScanLog).order_by(ScanLog.created_at.desc()).offset(offset).limit(limit).all()
    
    results = []
    for log in logs:
        # Check if user email needs to be populated or is anonymous
        email = "anonymous"
        if log.user:
            email = log.user.email
            
        results.append({
            "id": log.id,
            "url": log.url,
            "verdict": log.verdict,
            "risk_score": log.risk_score,
            "scan_time_ms": log.scan_time_ms,
            "created_at": log.created_at,
            "user_email": email
        })
    return results

@router.post("/blocklist/sync")
async def force_sync_threat_feeds(
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    """Force an immediate resynchronization of the threat intelligence feeds."""
    result = await fetch_and_sync_feeds(db)
    
    # Log admin action
    audit = AuditLog(
        user_id=admin.id,
        action="admin_blocklist_sync",
        details="Forced threat feed resynchronization manually"
    )
    db.add(audit)
    db.commit()
    
    return result

@router.post("/blocklist/entry", response_model=BlocklistEntryResponse)
def add_blocklist_entry(
    payload: BlocklistCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    """Manually add a malicious domain entry to the local blocklist database."""
    domain_lower = payload.domain.strip().lower()
    
    # Check if already exists
    existing = db.query(BlocklistEntry).filter(BlocklistEntry.domain == domain_lower).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain is already in the blocklist."
        )
        
    entry = BlocklistEntry(
        domain=domain_lower,
        category=payload.category,
        source=payload.source
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    
    # Log admin action
    audit = AuditLog(
        user_id=admin.id,
        action="admin_blocklist_add",
        details=f"Added custom blocklist domain: {domain_lower}"
    )
    db.add(audit)
    db.commit()
    
    return entry

@router.delete("/blocklist/entry/{domain}")
def remove_blocklist_entry(
    domain: str,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    """Manually remove a domain from the local blocklist database."""
    domain_lower = domain.strip().lower()
    
    entry = db.query(BlocklistEntry).filter(BlocklistEntry.domain == domain_lower).first()
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found in blocklist."
        )
        
    db.delete(entry)
    db.commit()
    
    # Log admin action
    audit = AuditLog(
        user_id=admin.id,
        action="admin_blocklist_remove",
        details=f"Removed custom blocklist domain: {domain_lower}"
    )
    db.add(audit)
    db.commit()
    
    return {"message": f"Successfully removed {domain_lower} from blocklist."}

@router.get("/audit-logs")
def get_audit_logs(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    """Retrieve security audit logs of administrative actions."""
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    return [
        {
            "id": log.id,
            "action": log.action,
            "ip_address": log.ip_address,
            "details": log.details,
            "created_at": log.created_at,
            "user_email": log.user.email if log.user else "system"
        }
        for log in logs
    ]
