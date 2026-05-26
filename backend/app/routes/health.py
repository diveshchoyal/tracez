"""TraceZ Backend — Health Check Router."""

from datetime import datetime, timezone
from fastapi import APIRouter
from app.config import settings

router = APIRouter(prefix="/api/health", tags=["Health"])

@router.get("")
def health_check():
    """Simple API status and environment info."""
    return {
        "status": "healthy",
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
