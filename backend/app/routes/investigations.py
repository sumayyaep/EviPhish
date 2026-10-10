"""Investigations API Routes for EviPhish.

Implements upload validation, forensic parsing, evidence persistence,
graph data generation, attack reconstruction, and gap analysis.
"""

import os
import re
import uuid
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status, Query
from sqlalchemy.orm import Session

from backend.app.core.config import settings, DATA_DIR
from backend.app.db.session import get_db
from backend.app.db.models import InvestigationModel, EvidenceItemModel
from backend.app.schemas.investigation import (
    InvestigationResponse,
    InvestigationDetailResponse,
)
from backend.app.parser.eml_parser import EmlParser
from backend.app.analyzer.classifier import EvidenceClassifier
from backend.app.analyzer.detector import PhishingDetector
from backend.app.analyzer.graph import EvidenceGraphBuilder
from backend.app.analyzer.reconstruction import AttackReconstructionBuilder
from backend.app.analyzer.gap_analyzer import EvidenceGapAnalyzer

UPLOADS_DIR = DATA_DIR / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

router = APIRouter(prefix="/investigations", tags=["Investigations"])

parser = EmlParser()
classifier = EvidenceClassifier()
detector = PhishingDetector()
graph_builder = EvidenceGraphBuilder()
reconstruction_builder = AttackReconstructionBuilder()
gap_analyzer = EvidenceGapAnalyzer()


def sanitize_filename(filename: str) -> str:
    """Strip dangerous characters and path traversal sequences from user filename."""
    name = Path(filename).name
    # Strip any characters except alphanumeric, dashes, dots, and underscores
    sanitized = re.sub(r'[^a-zA-Z0-9.\-_]', '_', name)
    return sanitized or "email_sample.eml"


def determine_initial_verdict(evidence_items: list[dict], parsed_data: dict) -> tuple[str, str]:
    """Deterministic, defensible rule-based verdict estimation.
    
    Adheres to the core rule: Evidence First, Conclusion Second.
    Never declares maliciousness without specific deceptive evidence.
    """
    has_deceptive_links = any(e.get("evidence_type") == "URL_TEXT_MISMATCH" for e in evidence_items)
    has_domain_mismatch = any(e.get("evidence_type") == "DOMAIN_ALIGNMENT_MISMATCH" for e in evidence_items)
    
    auth = parsed_data.get("auth_results", {})
    spf_status = auth.get("spf", {}).get("status", "UNKNOWN")
    dkim_status = auth.get("dkim", {}).get("status", "UNKNOWN")
    dmarc_status = auth.get("dmarc", {}).get("status", "UNKNOWN")

    if has_deceptive_links:
        verdict = "LIKELY_PHISHING"
        notes = (
            "Likely Phishing: Body contains hyperlink anchor text that deliberately misrepresents the actual "
            "destination domain, a characteristic pattern of deceptive phishing campaigns."
        )
    elif spf_status == "FAIL" or dkim_status == "FAIL" or dmarc_status == "FAIL":
        verdict = "SUSPICIOUS"
        notes = (
            f"Suspicious: One or more email authentication checks failed at receipt time (SPF={spf_status}, "
            f"DKIM={dkim_status}, DMARC={dmarc_status})."
        )
    elif spf_status == "PASS" and dkim_status == "PASS" and dmarc_status == "PASS" and not has_domain_mismatch:
        verdict = "NO_STRONG_INDICATORS_DETECTED"
        notes = (
            "No Strong Indicators Detected: Email passed SPF, DKIM, and DMARC authentication with aligned domains and "
            "no deceptive link mismatches observed."
        )
    elif has_domain_mismatch:
        verdict = "INCONCLUSIVE"
        notes = (
            "Inconclusive: Discrepancy observed between From and Return-Path/Reply-To domains. "
            "Could indicate third-party mailer or potential spoofing; requires additional authentication context."
        )
    else:
        verdict = "INCONCLUSIVE"
        notes = (
            "Inconclusive: Insufficient authentication telemetry (missing SPF/DKIM/DMARC headers) to reach "
            "a definitive conclusion. Review missing evidence gaps."
        )

    return verdict, notes


@router.post("/upload", response_model=InvestigationDetailResponse, status_code=status.HTTP_201_CREATED)
async def upload_investigation(
    file: UploadFile = File(...),
    title: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """Securely uploads and forensically analyzes an RFC 5322 .eml file."""
    # 1. Validate file extension
    original_name = file.filename or "unknown.eml"
    if not original_name.lower().endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Only .eml email files are supported."
        )

    # 2. Read content & enforce size limits (15 MB maximum)
    raw_content = await file.read()
    if len(raw_content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded email file is empty."
        )

    if len(raw_content) > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Uploaded file exceeds the maximum allowed size of {settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB."
        )

    # 3. Safe local storage handling
    sanitized_original = sanitize_filename(original_name)
    safe_stored_name = f"{uuid.uuid4().hex}.eml"
    storage_path = UPLOADS_DIR / safe_stored_name

    try:
        storage_path.write_bytes(raw_content)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to persist email on disk: {str(e)}"
        )

    # 4. Parse email forensically
    try:
        parsed_email = parser.parse_bytes(raw_content)
    except Exception as e:
        # Cleanup uploaded file if parsing fails
        if storage_path.exists():
            storage_path.unlink()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed email file: {str(e)}"
        )

    # 5. Extract structured evidence items
    evidence_items_data = classifier.classify_findings(parsed_email)

    # 6. Determine rule-based forensic verdict
    parsed_metadata = {
        "headers": parsed_email.headers,
        "all_headers_raw": parsed_email.all_headers_raw,
        "received_chain": parsed_email.received_chain,
        "auth_results": parsed_email.auth_results,
        "urls": parsed_email.urls,
        "domains": parsed_email.domains,
        "attachments": parsed_email.attachments,
        "discrepancies": parsed_email.discrepancies,
        "body_plain_preview": (parsed_email.body_plain[:5000] if parsed_email.body_plain else ""),
        "safe_body_text_preview": (parsed_email.safe_body_text[:5000] if parsed_email.safe_body_text else ""),
        "has_html": bool(parsed_email.body_html),
        "parsing_warnings": parsed_email.parsing_warnings
    }

    # 6. Run automatic phishing detection engine
    detection_result = detector.detect(parsed_email, evidence_items_data)
    verdict = detection_result["verdict"]
    summary_notes = detection_result["plain_explanation"]
    parsed_metadata["detection_result"] = detection_result

    # 7. Persist to SQLite
    investigation_id = str(uuid.uuid4())
    investigation_title = title.strip() if title and title.strip() else f"Investigation: {sanitized_original}"

    inv = InvestigationModel(
        id=investigation_id,
        title=investigation_title,
        filename=sanitized_original,
        file_size_bytes=len(raw_content),
        subject=parsed_email.headers.get("subject", "No Subject"),
        sender=parsed_email.headers.get("from", "Unknown"),
        recipient=parsed_email.headers.get("to", "Unknown"),
        verdict=verdict,
        summary_notes=summary_notes,
        storage_path=str(storage_path),
        parsed_metadata=parsed_metadata
    )
    db.add(inv)

    for item in evidence_items_data:
        ev_model = EvidenceItemModel(
            id=str(uuid.uuid4()),
            investigation_id=investigation_id,
            evidence_type=item["evidence_type"],
            observed_value=item["observed_value"],
            source_location=item["source_location"],
            classification=item["classification"],
            explanation=item["explanation"],
            limitations=item.get("limitations"),
            confidence_level=item.get("confidence_level"),
            extra_data=item.get("extra_data")
        )
        db.add(ev_model)

    db.commit()
    db.refresh(inv)

    return inv


@router.get("", response_model=list[InvestigationResponse])
def list_investigations(
    query: Optional[str] = Query(None, description="Search by title, subject, sender, or filename"),
    verdict: Optional[str] = Query(None, description="Filter by verdict"),
    db: Session = Depends(get_db)
):
    """Retrieve all email investigations with optional filtering."""
    q = db.query(InvestigationModel)
    
    if verdict:
        q = q.filter(InvestigationModel.verdict == verdict.upper())
        
    if query:
        search_pattern = f"%{query}%"
        q = q.filter(
            (InvestigationModel.title.ilike(search_pattern)) |
            (InvestigationModel.subject.ilike(search_pattern)) |
            (InvestigationModel.sender.ilike(search_pattern)) |
            (InvestigationModel.filename.ilike(search_pattern))
        )
        
    return q.order_by(InvestigationModel.created_at.desc()).all()


@router.get("/{investigation_id}", response_model=InvestigationDetailResponse)
def get_investigation(investigation_id: str, db: Session = Depends(get_db)):
    """Retrieve a single investigation case with all atomic evidence items."""
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' not found."
        )
    return inv


@router.get("/{investigation_id}/graph")
def get_investigation_graph(investigation_id: str, db: Session = Depends(get_db)):
    """Retrieve React Flow nodes and edges for evidence visualization."""
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found.")

    evidence_items = [
        {
            "id": item.id,
            "evidence_type": item.evidence_type,
            "observed_value": item.observed_value,
            "source_location": item.source_location,
            "classification": item.classification,
        }
        for item in inv.evidence_items
    ]

    graph_data = graph_builder.build_graph(inv.parsed_metadata or {}, evidence_items)
    return graph_data


@router.get("/{investigation_id}/reconstruction")
def get_investigation_reconstruction(investigation_id: str, db: Session = Depends(get_db)):
    """Retrieve reconstructed chronological attack sequence."""
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found.")

    evidence_items = [{"id": item.id, "type": item.evidence_type} for item in inv.evidence_items]
    timeline = reconstruction_builder.build_reconstruction(inv.parsed_metadata or {}, evidence_items)
    return timeline


@router.get("/{investigation_id}/gaps")
def get_investigation_gaps(investigation_id: str, db: Session = Depends(get_db)):
    """Retrieve missing-evidence gap analysis and recommendations."""
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found.")

    evidence_items = [{"id": item.id, "type": item.evidence_type} for item in inv.evidence_items]
    gaps = gap_analyzer.analyze_gaps(inv.parsed_metadata or {}, evidence_items)
    return gaps


@router.delete("/{investigation_id}")
def delete_investigation(investigation_id: str, db: Session = Depends(get_db)):
    """Safely delete an investigation, its evidence records, and disk file."""
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' not found."
        )

    # Safely remove stored .eml file from disk
    if inv.storage_path:
        storage_file = Path(inv.storage_path)
        if storage_file.exists():
            try:
                storage_file.unlink()
            except Exception:
                pass  # Continue to remove DB record even if file unlink had an issue

    db.delete(inv)
    db.commit()

    return {"deleted": True, "id": investigation_id}
