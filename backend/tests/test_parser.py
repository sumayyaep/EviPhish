"""Unit tests for EviPhish email forensics parsing and evidence classification."""

from pathlib import Path
import pytest
from backend.app.parser.eml_parser import EmlParser
from backend.app.analyzer.classifier import EvidenceClassifier

FIXTURES_DIR = Path(__file__).parent / "fixtures"
parser = EmlParser()
classifier = EvidenceClassifier()


def test_benign_sample_parsing():
    """Verify parsing and classification of benign RFC 5322 email."""
    file_bytes = (FIXTURES_DIR / "benign_sample.eml").read_bytes()
    data = parser.parse_bytes(file_bytes)

    # 1. Header verification
    assert "alice@company.example" in data.headers["from"]
    assert "bob@company.example" in data.headers["to"]
    assert "Project Roadmap" in data.headers["subject"]
    assert len(data.received_chain) >= 1

    # 2. Explicit Authentication Results
    assert data.auth_results["spf"]["status"] == "PASS"
    assert data.auth_results["dkim"]["status"] == "PASS"
    assert data.auth_results["dmarc"]["status"] == "PASS"

    # 3. Payload and URLs
    assert len(data.urls) >= 1
    assert "portal.company.example" in data.domains
    assert any(u["url"] == "https://portal.company.example/docs/roadmap-2026" for u in data.urls)

    # 4. Attachment Metadata
    assert len(data.attachments) == 1
    att = data.attachments[0]
    assert att["filename"] == "meeting_notes.txt"
    assert att["size_bytes"] > 0
    assert len(att["sha256"]) == 64

    # 5. Evidence Classification
    evidence = classifier.classify_findings(data)
    assert len(evidence) > 5
    # Ensure all items have stable structure
    for item in evidence:
        assert item["id"].startswith("EVID-")
        assert item["classification"] in ("OBSERVED", "INFERRED", "UNKNOWN")
        assert "explanation" in item
        assert "limitations" in item


def test_suspicious_phishing_sample_parsing():
    """Verify detection of phishing indicators: deceptive links, failed auth, sender discrepancies."""
    file_bytes = (FIXTURES_DIR / "suspicious_phishing_sample.eml").read_bytes()
    data = parser.parse_bytes(file_bytes)

    # 1. Authentication failures
    assert data.auth_results["spf"]["status"] == "FAIL"
    assert data.auth_results["dmarc"]["status"] == "FAIL"

    # 2. Deceptive anchor text vs href mismatch
    assert len(data.discrepancies) >= 1
    anchor_mismatch = next(
        (d for d in data.discrepancies if d["type"] == "ANCHOR_TEXT_DESTINATION_MISMATCH"),
        None
    )
    assert anchor_mismatch is not None
    assert "secure-banking.example" in anchor_mismatch["apparent_domain"]
    assert "credential-harvest.example" in anchor_mismatch["target_domain"]

    # 3. Domain alignment mismatches
    domain_mismatches = [d for d in data.discrepancies if "MISMATCH" in d["type"]]
    assert len(domain_mismatches) >= 2

    # 4. Evidence Classification
    evidence = classifier.classify_findings(data)
    types = [e["evidence_type"] for e in evidence]
    assert "URL_TEXT_MISMATCH" in types
    assert "DOMAIN_ALIGNMENT_MISMATCH" in types

    # Verify classification of deceptive link as INFERRED
    mismatch_ev = next(e for e in evidence if e["evidence_type"] == "URL_TEXT_MISMATCH")
    assert mismatch_ev["classification"] == "INFERRED"


def test_missing_auth_headers_classified_unknown():
    """Verify that absent authentication headers are strictly labeled UNKNOWN, not PASS or FAIL."""
    file_bytes = (FIXTURES_DIR / "minimal_no_auth.eml").read_bytes()
    data = parser.parse_bytes(file_bytes)

    # Auth status should be strictly UNKNOWN
    assert data.auth_results["spf"]["status"] == "UNKNOWN"
    assert data.auth_results["dkim"]["status"] == "UNKNOWN"
    assert data.auth_results["dmarc"]["status"] == "UNKNOWN"

    evidence = classifier.classify_findings(data)
    auth_items = [e for e in evidence if e["evidence_type"] in ("AUTH_SPF", "AUTH_DKIM", "AUTH_DMARC")]

    assert len(auth_items) == 3
    for auth_ev in auth_items:
        assert auth_ev["classification"] == "UNKNOWN"
        assert "not recorded" in auth_ev["observed_value"].lower()


def test_malformed_email_handling():
    """Verify graceful rejection of invalid or empty email bytes."""
    with pytest.raises(ValueError, match="empty"):
        parser.parse_bytes(b"")

    with pytest.raises(ValueError, match="empty"):
        parser.parse_bytes(b"   \n\t  ")
