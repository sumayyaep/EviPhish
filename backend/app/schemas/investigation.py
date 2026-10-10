"""Pydantic schemas for Investigations."""
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, ConfigDict
from backend.app.schemas.evidence import EvidenceItemResponse

class InvestigationBase(BaseModel):
    title: str
    filename: str

class InvestigationCreate(InvestigationBase):
    pass

class InvestigationResponse(InvestigationBase):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    file_size_bytes: int
    created_at: datetime
    subject: Optional[str] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None
    verdict: Optional[str] = "UNDER_INVESTIGATION"
    summary_notes: Optional[str] = None
    parsed_metadata: Optional[dict[str, Any]] = None

class InvestigationDetailResponse(InvestigationResponse):
    evidence_items: list[EvidenceItemResponse] = []
