from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class ScanHistoryItem(BaseModel):
    id: str
    filename: str
    type: str
    verdict: str
    risk_score: int
    created_at: datetime

    class Config:
        orm_mode = True

class APIKeyUpdate(BaseModel):
    openai_key: Optional[str] = None
    virustotal_key: Optional[str] = None

class ThreatItem(BaseModel):
    id: str
    name: str
    category: str
    severity: str
    description: str
    verdict_text: str
    features: List[str]

    class Config:
        orm_mode = True
