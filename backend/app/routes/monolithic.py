"""TraceZ Backend — Monolithic SPA Compatibility Router."""

import asyncio
import json
import os
import secrets
import uuid
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Response, Request, UploadFile, File, Cookie
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db, Threat, Scan, User
from app.utils.scanner import ScanOrchestrator

router = APIRouter(tags=["Monolithic Compatibility"])

# Active SSE Queues
active_queues = {}

# User keys cache
user_keys = {
    "openai_key": "MOCK_KEY",
    "virustotal_key": "MOCK_KEY"
}

# Upload directory
UPLOAD_DIR = "C:/Users/Administrator/.gemini/antigravity/scratch/tracez/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Helper for monolithic auth
def get_monolithic_user(session_user: str = Cookie(None), db: Session = Depends(get_db)):
    if not session_user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    user = db.query(User).filter(User.email == session_user).first()
    if not user:
        raise HTTPException(status_code=401, detail="Session not found.")
    return user

def check_monolithic_admin(session_user: str = Cookie(None), db: Session = Depends(get_db)):
    user = get_monolithic_user(session_user, db)
    if user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Forbidden. Admin authorization required.")
    return user

# --- SETTINGS KEYS ---

@router.post("/api/settings/keys")
def save_settings(payload: dict, session_user: str = Cookie(None)):
    if not session_user:
        raise HTTPException(status_code=401, detail="Please log in first.")
    user_keys["openai_key"] = payload.get("openai_key", "")
    user_keys["virustotal_key"] = payload.get("virustotal_key", "")
    return {"status": "success", "message": "API configurations updated successfully."}

@router.get("/api/settings/keys")
def get_settings(session_user: str = Cookie(None)):
    if not session_user:
        raise HTTPException(status_code=401, detail="Please log in first.")
    def mask(s):
        return f"{s[:6]}...{s[-4:]}" if len(s) > 10 else s
    return {
        "openai_key": mask(user_keys["openai_key"]),
        "virustotal_key": mask(user_keys["virustotal_key"])
    }

# --- SCANNING ENDPOINTS ---

async def run_scan_and_save(orchestrator, file_path, filename, task_id, queue, db):
    await orchestrator.scan_file_stream(file_path, filename, queue)
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception:
        pass

async def run_url_scan_and_save(orchestrator, url, task_id, queue, db):
    await orchestrator.scan_url_stream(url, queue)

@router.post("/api/scan/file")
async def upload_scan_file(
    file: UploadFile = File(...),
    session_user: str = Cookie(None),
    db: Session = Depends(get_db)
):
    if not session_user:
        raise HTTPException(status_code=401, detail="Authentication required to perform scans.")
        
    task_id = str(uuid.uuid4())
    filename = file.filename
    file_path = os.path.join(UPLOAD_DIR, f"{task_id}_{filename}")
    
    # Save uploaded file in 8KB chunks
    try:
        with open(file_path, "wb") as buffer:
            while True:
                chunk = await file.read(8192)
                if not chunk:
                    break
                buffer.write(chunk)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File saving error: {str(e)}")

    # Create async event queue for SSE stream
    event_queue = asyncio.Queue()
    active_queues[task_id] = event_queue

    # Set up orchestrator and run background task
    orchestrator = ScanOrchestrator(
        db=db,
        openai_key=user_keys["openai_key"],
        vt_key=user_keys["virustotal_key"]
    )
    
    asyncio.create_task(run_scan_and_save(orchestrator, file_path, filename, task_id, event_queue, db))
    
    return {"task_id": task_id, "filename": filename}

@router.post("/api/scan/url")
async def upload_scan_url(
    payload: dict,
    session_user: str = Cookie(None),
    db: Session = Depends(get_db)
):
    if not session_user:
        raise HTTPException(status_code=401, detail="Authentication required to perform scans.")
        
    url = payload.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="URL field is required.")
        
    task_id = str(uuid.uuid4())
    event_queue = asyncio.Queue()
    active_queues[task_id] = event_queue
    
    orchestrator = ScanOrchestrator(
        db=db,
        openai_key=user_keys["openai_key"],
        vt_key=user_keys["virustotal_key"]
    )
    
    asyncio.create_task(run_url_scan_and_save(orchestrator, url, task_id, event_queue, db))
    
    return {"task_id": task_id, "url": url}

@router.get("/api/scan/stream/{task_id}")
async def get_scan_stream(task_id: str):
    if task_id not in active_queues:
        raise HTTPException(status_code=404, detail="Task stream queue not found.")

    queue = active_queues[task_id]

    async def event_generator():
        try:
            while True:
                event = await queue.get()
                yield f"event: {event['event']}\ndata: {json.dumps(event['data'])}\n\n"
                
                # Check for terminal events to clean up queue
                if event["event"] in ("done", "error"):
                    break
        except asyncio.CancelledError:
            pass
        finally:
            active_queues.pop(task_id, None)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

# --- TRZ SIGNATURE DATABASE ---

@router.get("/api/trz/list")
def get_trz_registry(db: Session = Depends(get_db)):
    threats = db.query(Threat).all()
    result = []
    for t in threats:
        result.append({
            "id": t.id,
            "name": t.name,
            "category": t.category,
            "severity": t.severity,
            "description": t.description,
            "verdict_text": t.verdict_text,
            "features": json.loads(t.features_json) if t.features_json else []
        })
    return result

# --- SCAN REPORTS HISTORY ---

@router.get("/api/scans/history")
def get_scans_history(session_user: str = Cookie(None), db: Session = Depends(get_db)):
    if not session_user:
        raise HTTPException(status_code=401, detail="Authentication required.")
        
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(20).all()
    result = []
    for s in scans:
        result.append({
            "id": s.id,
            "filename": s.filename,
            "type": s.type,
            "verdict": s.verdict,
            "risk_score": s.risk_score,
            "created_at": s.created_at.strftime("%Y-%m-%d %H:%M:%S") if s.created_at else None
        })
    return result

# --- ADMIN PANEL METRICS AND ACTIONS ---

@router.get("/api/admin/metrics")
def get_monolithic_admin_metrics(
    admin: User = Depends(check_monolithic_admin),
    db: Session = Depends(get_db)
):
    total_users = db.query(User).count()
    total_scans = db.query(Scan).count()
    danger_scans = db.query(Scan).filter(Scan.verdict == "DANGEROUS").count()
    suspicious_scans = db.query(Scan).filter(Scan.verdict == "SUSPICIOUS").count()
    safe_scans = db.query(Scan).filter(Scan.verdict == "SAFE").count()
    
    recent_scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(15).all()
    scan_list = []
    for s in recent_scans:
        scan_list.append({
            "id": s.id,
            "filename": s.filename,
            "type": s.type,
            "verdict": s.verdict,
            "risk_score": s.risk_score,
            "created_at": s.created_at.strftime("%Y-%m-%d %H:%M") if s.created_at else None
        })
        
    return {
        "metrics": {
            "total_users": total_users,
            "total_scans": total_scans,
            "danger_scans": danger_scans,
            "suspicious_scans": suspicious_scans,
            "safe_scans": safe_scans,
            "average_scan_time_ms": 1200
        },
        "scans": scan_list
    }

@router.post("/api/admin/history/wipe")
def wipe_scan_history(
    admin: User = Depends(check_monolithic_admin),
    db: Session = Depends(get_db)
):
    try:
        db.query(Scan).delete()
        db.commit()
        return {"status": "success", "message": "Scan history database wiped successfully."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database wiping error: {str(e)}")

@router.post("/api/admin/threat/add")
def add_custom_threat(
    payload: dict,
    admin: User = Depends(check_monolithic_admin),
    db: Session = Depends(get_db)
):
    threat_id = payload.get("id")
    name = payload.get("name")
    category = payload.get("category", "APK")
    severity = payload.get("severity", "DANGEROUS")
    description = payload.get("description", "")
    verdict_text = payload.get("verdict_text", "")
    features = payload.get("features", [])

    if not threat_id or not name or not features:
        raise HTTPException(status_code=400, detail="ID, Name, and Features list are required.")

    if not threat_id.startswith("TRZ-"):
        threat_id = f"TRZ-{category}-{threat_id[:12]}"

    existing = db.query(Threat).filter(Threat.id == threat_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Threat signature ID already exists.")

    new_threat = Threat(
        id=threat_id,
        name=name,
        category=category,
        severity=severity,
        description=description,
        verdict_text=verdict_text,
        features_json=json.dumps(features)
    )
    
    try:
        db.add(new_threat)
        db.commit()
        return {"status": "success", "message": f"Threat signature {threat_id} added successfully."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
