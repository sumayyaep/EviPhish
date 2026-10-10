"""Forensic Report Export API Routes.

Generates structured, downloadable evidence-based forensic investigation reports.
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.session import get_db
from backend.app.db.models import InvestigationModel
from backend.app.analyzer.graph import EvidenceGraphBuilder
from backend.app.analyzer.reconstruction import AttackReconstructionBuilder
from backend.app.analyzer.gap_analyzer import EvidenceGapAnalyzer

router = APIRouter(prefix="/reports", tags=["Reports"])

graph_builder = EvidenceGraphBuilder()
reconstruction_builder = AttackReconstructionBuilder()
gap_analyzer = EvidenceGapAnalyzer()


@router.get("/{investigation_id}/export")
def export_investigation_report(investigation_id: str, db: Session = Depends(get_db)):
    """Generate and export a comprehensive forensic evidence report."""
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' not found."
        )

    metadata = inv.parsed_metadata or {}
    evidence_items = [
        {
            "id": item.id,
            "evidence_type": item.evidence_type,
            "observed_value": item.observed_value,
            "source_location": item.source_location,
            "classification": item.classification,
            "explanation": item.explanation,
            "limitations": item.limitations,
            "confidence_level": item.confidence_level,
            "extra_data": item.extra_data,
        }
        for item in inv.evidence_items
    ]

    timeline = reconstruction_builder.build_reconstruction(metadata, evidence_items)
    gaps = gap_analyzer.analyze_gaps(metadata, evidence_items)
    
    # 1. Build Graph Relationships
    graph_data = graph_builder.build_graph(metadata, evidence_items)
    
    # 2. Extract Detection Info
    detection = metadata.get("detection_result", {})
    
    # 3. Securely scrub metadata (preventing exposure of local paths or keys)
    def _scrub(obj):
        if isinstance(obj, dict):
            return {k: _scrub(v) for k, v in obj.items() if not str(k).lower().endswith("api_key")}
        elif isinstance(obj, list):
            return [_scrub(v) for v in obj]
        elif isinstance(obj, str):
            # Check if looks like a Windows or Linux absolute path
            if "C:\\" in obj or (obj.startswith("/") and "home" in obj):
                return "<REDACTED_LOCAL_PATH>"
        return obj

    report_payload = {
        "report_metadata": {
            "platform": settings.APP_NAME,
            "platform_version": settings.APP_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_id": f"RPT-{inv.id[:8].upper()}",
            "investigation_id": inv.id,
            "case_title": inv.title,
        },
        "executive_summary": {
            "original_filename": inv.filename,
            "file_size_bytes": inv.file_size_bytes,
            "subject": inv.subject,
            "sender": inv.sender,
            "reply_to": metadata.get("headers", {}).get("reply_to", ""),
            "return_path": metadata.get("headers", {}).get("return_path", ""),
            "recipient": inv.recipient,
            "verdict": inv.verdict,
            "score": detection.get("score"),
            "confidence": detection.get("confidence"),
            "verdict_summary": inv.summary_notes,
        },
        "authentication_summary": {
            "spf": metadata.get("auth_results", {}).get("spf"),
            "dkim": metadata.get("auth_results", {}).get("dkim"),
            "dmarc": metadata.get("auth_results", {}).get("dmarc"),
            "raw_auth_headers": metadata.get("auth_results", {}).get("raw_auth_headers", []),
        },
        "indicators": {
            "extracted_urls_count": len(metadata.get("urls", [])),
            "extracted_urls": metadata.get("urls", []),
            "extracted_domains_count": len(metadata.get("domains", [])),
            "extracted_domains": metadata.get("domains", []),
            "attachments_count": len(metadata.get("attachments", [])),
            "attachments": metadata.get("attachments", []),
            "detected_discrepancies": metadata.get("discrepancies", []),
        },
        "classified_evidence_items": _scrub(evidence_items),
        "detector_hypotheses": _scrub(detection.get("key_indicators", [])),
        "graph_relationships": _scrub(graph_data),
        "attack_sequence_reconstruction": _scrub(timeline),
        "evidence_gaps_and_recommendations": gaps,
        "forensic_methodology_and_limitations": {
            "core_principle": "Evidence First, Conclusion Second",
            "disclaimer": (
                "This forensic report is generated through static analysis of the submitted RFC 5322 email file. "
                "Observations represent immutable artifact data. Inferences are bounded by recorded evidence. "
                "This report explicitly does not assume victim compromise, credential disclosure, or malware execution "
                "without secondary endpoint or network gateway telemetry."
            ),
            "recommended_next_steps": [
                "Submit extracted domains to DNS threat intelligence feeds via safe passive lookups.",
                "Correlate recipient email address against proxy and endpoint EDR logs for click verification.",
                "If SPF/DKIM are missing, query domain authoritative DNS servers directly.",
                "Submit attachment hashes to internal malware intelligence databases."
            ]
        }
    }

    return report_payload
