import pytest
from pathlib import Path
from unittest.mock import patch
import socket

from backend.app.parser.eml_parser import EmlParser
from backend.app.analyzer.classifier import EvidenceClassifier
from backend.app.analyzer.detector import PhishingDetector

FIXTURES_DIR = Path(__file__).parent / "fixtures"

@pytest.fixture
def parser():
    return EmlParser()

@pytest.fixture
def classifier():
    return EvidenceClassifier()

@pytest.fixture
def detector():
    return PhishingDetector()

@pytest.fixture(autouse=True)
def prevent_network_calls(monkeypatch):
    """Ensure no URL is visited and no DNS lookup is performed."""
    def block_socket(*args, **kwargs):
        raise RuntimeError("Network calls are forbidden during forensic analysis!")
    
    monkeypatch.setattr(socket, "socket", block_socket)
    monkeypatch.setattr(socket, "gethostbyname", block_socket)

def test_e2e_benign_sample(parser, classifier, detector):
    """Test benign sample parses safely and gets NO_STRONG_INDICATORS_DETECTED."""
    raw = (FIXTURES_DIR / "benign_sample.eml").read_bytes()
    parsed = parser.parse_bytes(raw)
    
    # Assert successful auth does NOT automatically imply safe
    # It must be evaluated by the detector to ensure no severe content risk
    assert parsed.auth_results["dmarc"]["status"] == "PASS"
    
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    
    assert result["verdict"] == "NO_STRONG_INDICATORS_DETECTED"
    
    # Evidence IDs and explanations preserved
    assert "plain_explanation" in result
    assert isinstance(result["key_indicators"], list)

def test_e2e_suspicious_phishing_sample(parser, classifier, detector):
    """Test phishing sample parses safely and gets LIKELY_PHISHING or SUSPICIOUS."""
    raw = (FIXTURES_DIR / "suspicious_phishing_sample.eml").read_bytes()
    parsed = parser.parse_bytes(raw)
    
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    
    assert result["verdict"] in ("LIKELY_PHISHING", "SUSPICIOUS")
    
    # Ensure evidence IDs and explanations are preserved
    assert len(result["key_indicators"]) > 0
    indicator = result["key_indicators"][0]
    assert "id" in indicator
    assert "description" in indicator
    assert "evidence_ids" in indicator
    assert len(indicator["evidence_ids"]) > 0

def test_e2e_minimal_no_auth(parser, classifier, detector):
    """Test missing auth headers do not automatically imply phishing."""
    raw = (FIXTURES_DIR / "minimal_no_auth.eml").read_bytes()
    parsed = parser.parse_bytes(raw)
    
    assert parsed.auth_results["spf"]["status"] == "UNKNOWN"
    assert parsed.auth_results["dkim"]["status"] == "UNKNOWN"
    assert parsed.auth_results["dmarc"]["status"] == "UNKNOWN"
    
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    
    # Missing auth should be INCONCLUSIVE, not automatically LIKELY_PHISHING
    assert result["verdict"] == "INCONCLUSIVE"
    assert result["confidence"] == "LOW"
    assert "Inconclusive" in result["plain_explanation"]

def test_e2e_parsing_fails_safely(parser):
    """Ensure parsing fails safely on empty bytes and parses weird strings safely."""
    with pytest.raises(ValueError):
        parser.parse_bytes(b"")

    # The standard library email parser accepts arbitrary text as a body without headers.
    parsed = parser.parse_bytes(b"Not an email at all")
    assert parsed.body_plain.strip() == "Not an email at all"
