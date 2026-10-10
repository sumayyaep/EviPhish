import datetime
import uuid
from sqlalchemy import Column, String, DateTime, Text, JSON, ForeignKey, Integer
from sqlalchemy.orm import relationship
from backend.app.db.session import Base

def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)

class InvestigationModel(Base):
    """Represents a forensic email investigation case."""
    __tablename__ = "investigations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False)
    filename = Column(String(255), nullable=False)
    file_size_bytes = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    
    # High-level forensic summary
    subject = Column(String(500), nullable=True)
    sender = Column(String(255), nullable=True)
    recipient = Column(String(255), nullable=True)
    verdict = Column(String(50), default="UNDER_INVESTIGATION")  # SUSPICIOUS, BENIGN, INCONCLUSIVE
    summary_notes = Column(Text, nullable=True)
    storage_path = Column(String(500), nullable=True)
    
    # Raw parsed data stored as JSON for fidelity
    parsed_metadata = Column(JSON, nullable=True)

    # Relationships
    evidence_items = relationship("EvidenceItemModel", back_populates="investigation", cascade="all, delete-orphan")


class EvidenceItemModel(Base):
    """Represents an atomic, verifiable evidence observation or inference."""
    __tablename__ = "evidence_items"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    
    evidence_type = Column(String(100), nullable=False)  # HEADER, URL, DOMAIN, AUTH, ATTACHMENT, BODY_TEXT
    observed_value = Column(Text, nullable=False)
    source_location = Column(String(255), nullable=False)  # e.g., 'Header: Authentication-Results'
    classification = Column(String(50), nullable=False)    # OBSERVED, INFERRED, UNKNOWN
    explanation = Column(Text, nullable=False)
    limitations = Column(Text, nullable=True)
    confidence_level = Column(String(50), nullable=True)   # HIGH, MEDIUM, LOW, or None
    
    extra_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    investigation = relationship("InvestigationModel", back_populates="evidence_items")
