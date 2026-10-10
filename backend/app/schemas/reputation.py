from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class ReputationRequest(BaseModel):
    email: str = Field(..., description="The email address to check")
    consent_given: bool = Field(False, description="User consent to query external providers")

class SyntaxValidation(BaseModel):
    is_valid_format: bool
    normalized_email: Optional[str] = None
    domain: Optional[str] = None
    error: Optional[str] = None

class ReputationResult(BaseModel):
    address: str
    syntax: SyntaxValidation
    verdict: str = Field(..., description="REPORTED_SUSPICIOUS, NO_REPORTS_FOUND, or INCONCLUSIVE")
    sources_checked: List[str] = []
    findings: List[str] = []
    confidence: str
    explanation: str
    limitations: List[str] = []
    metadata: Dict[str, Any] = {}
