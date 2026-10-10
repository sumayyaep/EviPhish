"""Automated tests for PhishingDetector engine."""

from pathlib import Path
import pytest
from backend.app.parser.eml_parser import EmlParser, ForensicEmailData
from backend.app.analyzer.classifier import EvidenceClassifier
from backend.app.analyzer.detector import PhishingDetector

FIXTURES_DIR = Path(__file__).parent / "fixtures"

parser = EmlParser()
classifier = EvidenceClassifier()
detector = PhishingDetector()


def test_detector_phishing_sample_automatic_verdict():
    raw = (FIXTURES_DIR / "suspicious_phishing_sample.eml").read_bytes()
    parsed = parser.parse_bytes(raw)
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["verdict"] == "LIKELY_PHISHING"
    assert result["score"] >= 50
    assert "Likely Phishing" in result["plain_explanation"]


def test_detector_benign_sample_not_flagged_phishing():
    raw = (FIXTURES_DIR / "benign_sample.eml").read_bytes()
    parsed = parser.parse_bytes(raw)
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["verdict"] == "NO_STRONG_INDICATORS_DETECTED"
    assert result["score"] < 25


def test_detector_ambiguous_minimal_email_returns_inconclusive():
    raw = (FIXTURES_DIR / "minimal_no_auth.eml").read_bytes()
    parsed = parser.parse_bytes(raw)
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["verdict"] == "INCONCLUSIVE"
    assert result["confidence"] == "LOW"


def test_detector_does_not_claim_compromise():
    raw = (FIXTURES_DIR / "suspicious_phishing_sample.eml").read_bytes()
    parsed = parser.parse_bytes(raw)
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    explanation = result["plain_explanation"].lower()
    assert "compromised" not in explanation
    assert "password stolen" not in explanation


# --- Parameterized Edge Case Tests ---

def create_mock_parsed_email(
    spf="UNKNOWN", dkim="UNKNOWN", dmarc="UNKNOWN",
    reply_mismatch=False, return_mismatch=False,
    body_text="", has_html_att=False, has_exe_att=False,
    anchor_mismatch=False, urls=None, html_filename="invoice.html"
) -> ForensicEmailData:
    data = ForensicEmailData()
    data.auth_results["spf"]["status"] = spf
    data.auth_results["dkim"]["status"] = dkim
    data.auth_results["dmarc"]["status"] = dmarc
    
    if reply_mismatch:
        data.discrepancies.append({"type": "FROM_REPLYTO_DOMAIN_MISMATCH", "description": "Reply-To differs"})
    if return_mismatch:
        data.discrepancies.append({"type": "FROM_RETURNPATH_DOMAIN_MISMATCH", "description": "Return-Path differs"})
    if anchor_mismatch:
        data.discrepancies.append({"type": "ANCHOR_TEXT_DESTINATION_MISMATCH", "apparent_domain": "a.com", "target_domain": "b.com"})
        
    data.body_plain = body_text
    data.safe_body_text = body_text
    
    if has_html_att:
        data.attachments.append({"filename": html_filename, "content_type": "text/html", "size_bytes": 100, "sha256": "x"})
    if has_exe_att:
        data.attachments.append({"filename": "invoice.exe", "content_type": "application/x-msdownload", "size_bytes": 100, "sha256": "x"})
        
    if urls:
        for u in urls:
            data.urls.append({"url": u, "domain": "example.com"})
            
    return data

def test_spf_fail_with_dmarc_pass():
    """SPF FAIL with DMARC PASS should not be an auth failure."""
    parsed = create_mock_parsed_email(spf="FAIL", dmarc="PASS")
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["verdict"] == "NO_STRONG_INDICATORS_DETECTED"
    assert result["score"] == 0
    assert any("explicitly passed" in m for m in result["mitigating_factors"])

def test_spf_fail_with_dkim_pass_missing_dmarc():
    """SPF FAIL with DKIM PASS and missing DMARC should not trigger full failure."""
    parsed = create_mock_parsed_email(spf="FAIL", dkim="PASS", dmarc="UNKNOWN")
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["verdict"] == "NO_STRONG_INDICATORS_DETECTED"
    assert result["score"] == 0
    assert any("SPF failed but DKIM or DMARC passed" in m for m in result["mitigating_factors"])

def test_missing_authentication_results():
    """All unknown should give INCONCLUSIVE."""
    parsed = create_mock_parsed_email(spf="UNKNOWN", dkim="UNKNOWN", dmarc="UNKNOWN")
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["verdict"] == "INCONCLUSIVE"
    assert result["confidence"] == "LOW"

def test_legitimate_newsletter_return_path():
    """Return-Path mismatch alone doesn't trigger SUSPICIOUS."""
    parsed = create_mock_parsed_email(spf="PASS", dkim="PASS", dmarc="PASS", return_mismatch=True)
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["verdict"] == "NO_STRONG_INDICATORS_DETECTED"
    # base mismatch is 5, but DMARC pass is -20, so 0
    assert result["score"] == 0
    assert any("Return-Path mismatch detected" in m for m in result["mitigating_factors"])

def test_reply_to_mismatch():
    """Reply-To mismatch adds risk points (15) but DMARC PASS reduces it, keeping it safe."""
    parsed = create_mock_parsed_email(spf="PASS", dkim="PASS", dmarc="PASS", reply_mismatch=True)
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["verdict"] == "NO_STRONG_INDICATORS_DETECTED"
    # 15 - 20 = 0
    assert result["score"] == 0
    indicator_ids = [ind["id"] for ind in result["key_indicators"]]
    assert "IND-REPLYTO-MISMATCH" in indicator_ids

def test_html_attachment_with_generic_urgency():
    """HTML attachment (5) + urgency (10) = 15. Not suspicious, even without DMARC PASS mitigation (if applied)."""
    parsed = create_mock_parsed_email(dmarc="PASS", has_html_att=True, body_text="This is urgent.")
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["verdict"] == "NO_STRONG_INDICATORS_DETECTED"
    assert result["score"] == 0

def test_credential_lure_with_deceptive_link():
    """Credential lure (15) + anchor mismatch (45) = 60. Should be LIKELY_PHISHING, even with DMARC pass."""
    parsed = create_mock_parsed_email(dmarc="PASS", body_text="Verify your credentials", anchor_mismatch=True)
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["verdict"] == "LIKELY_PHISHING"
    assert result["score"] == 60
    assert result["confidence"] == "HIGH"

def test_legitimate_deep_subdomain():
    """Deep subdomain shouldn't penalize."""
    parsed = create_mock_parsed_email(dmarc="PASS", urls=["https://us-west-2.console.aws.amazon.com/login"])
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["verdict"] == "NO_STRONG_INDICATORS_DETECTED"
    assert result["score"] == 0

def test_score_thresholds():
    # Exactly 25
    parsed = create_mock_parsed_email(dmarc="UNKNOWN", body_text="verify your credentials and this is urgent")
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["score"] == 25
    assert result["verdict"] == "SUSPICIOUS"

    # Exactly 50 (auth fail 30 + exe att 30 = 60)
    parsed2 = create_mock_parsed_email(dmarc="FAIL", has_exe_att=True)
    evidence2 = classifier.classify_findings(parsed2)
    result2 = detector.detect(parsed2, evidence2)
    assert result2["score"] == 60
    assert result2["verdict"] == "LIKELY_PHISHING"

def test_conflicting_indicators():
    """DMARC PASS (0 mitigation because severe content) + exe attachment (30) + credential lure (15) = 45 -> SUSPICIOUS."""
    parsed = create_mock_parsed_email(dmarc="PASS", body_text="verify your credentials", has_exe_att=True)
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["score"] == 45
    assert result["verdict"] == "SUSPICIOUS"

def test_p03_false_negative_fix():
    """Credential lure + HTML attachment with DMARC pass must NOT be benign (score >= 25)."""
    parsed = create_mock_parsed_email(dmarc="PASS", body_text="login to update billing", has_html_att=True)
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["verdict"] in ("SUSPICIOUS", "LIKELY_PHISHING")
    assert result["score"] == 30

def test_p07_false_negative_fix():
    """Executable attachment + Urgent language with DMARC pass must NOT be benign (score >= 25)."""
    parsed = create_mock_parsed_email(dmarc="PASS", body_text="urgent invoice", has_exe_att=True)
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["verdict"] in ("SUSPICIOUS", "LIKELY_PHISHING")
    assert result["score"] == 40

def test_b12_legitimate_secure_message_context():
    """Legitimate secure message context (HTML att + credential lure) is SUSPICIOUS because filenames cannot be trusted."""
    parsed = create_mock_parsed_email(dmarc="PASS", has_html_att=True, html_filename="SecureMessageAtt.html", body_text="verify identity")
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["verdict"] == "SUSPICIOUS"
    assert result["score"] >= 25

def test_malicious_html_named_secure_message():
    """An attacker naming their phishing file SecureMessageAtt.html must still be caught."""
    parsed = create_mock_parsed_email(dmarc="PASS", has_html_att=True, html_filename="SecureMessageAtt.html", body_text="login to update billing")
    evidence = classifier.classify_findings(parsed)
    result = detector.detect(parsed, evidence)
    assert result["verdict"] == "SUSPICIOUS"
    assert result["score"] >= 25
