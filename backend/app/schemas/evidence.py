"""Pydantic schemas for atomic evidence items."""
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, ConfigDict

class EvidenceItemBase(BaseModel):
    evidence_type: str
    observed_value: str
    source_location: str
    classification: str  # OBSERVED, INFERRED, UNKNOWN
    explanation: str
    limitations: Optional[str] = None
    confidence_level: Optional[str] = None
    extra_data: Optional[dict[str, Any]] = None

class EvidenceItemCreate(EvidenceItemBase):
    pass

class EvidenceItemResponse(EvidenceItemBase):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    investigation_id: str
    created_at: datetime
