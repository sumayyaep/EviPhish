"""API Tests for EviPhish Investigation Endpoints.

Covers upload validation, oversized file handling, non-eml rejection,
retrieval, graph data, timeline, gaps, report export, and safe deletion.
"""

from pathlib import Path
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app, raise_server_exceptions=False)
FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_health_endpoint():
    """Verify health endpoint returns status 200 and valid JSON."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_upload_benign_investigation():
    """Verify successful upload, parsing, and classification of benign email."""
    file_path = FIXTURES_DIR / "benign_sample.eml"
    with open(file_path, "rb") as f:
        response = client.post(
            "/api/investigations/upload",
            files={"file": ("benign_sample.eml", f, "message/rfc822")},
            data={"title": "Test Benign Case"}
        )

    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "Test Benign Case"
    assert data["verdict"] == "NO_STRONG_INDICATORS_DETECTED"
    assert "company.example" in data["sender"]
    assert len(data["evidence_items"]) > 0
    assert "detection_result" in data["parsed_metadata"]
    assert data["parsed_metadata"]["detection_result"]["verdict"] == "NO_STRONG_INDICATORS_DETECTED"

    inv_id = data["id"]

    # Verify retrieval
    get_res = client.get(f"/api/investigations/{inv_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == inv_id


def test_upload_suspicious_phishing_investigation():
    """Verify upload of phishing email results in LIKELY_PHISHING verdict with evidence."""
    file_path = FIXTURES_DIR / "suspicious_phishing_sample.eml"
    with open(file_path, "rb") as f:
        response = client.post(
            "/api/investigations/upload",
            files={"file": ("suspicious_phishing_sample.eml", f, "message/rfc822")},
        )

    assert response.status_code == 201
    data = response.json()
    assert data["verdict"] in ("LIKELY_PHISHING", "SUSPICIOUS")
    assert "detection_result" in data["parsed_metadata"]
    assert data["parsed_metadata"]["detection_result"]["verdict"] == "LIKELY_PHISHING"
    assert len(data["parsed_metadata"]["detection_result"]["key_indicators"]) >= 2

    inv_id = data["id"]

    # Verify Graph endpoint
    graph_res = client.get(f"/api/investigations/{inv_id}/graph")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data
    assert len(graph_data["nodes"]) >= 5

    # Verify Reconstruction endpoint
    recon_res = client.get(f"/api/investigations/{inv_id}/reconstruction")
    assert recon_res.status_code == 200
    timeline = recon_res.json()
    assert len(timeline) >= 4
    # Ensure hypothetical events are marked
    hypo_events = [e for e in timeline if e.get("is_hypothetical")]
    assert len(hypo_events) >= 1

    # Verify Gaps endpoint
    gaps_res = client.get(f"/api/investigations/{inv_id}/gaps")
    assert gaps_res.status_code == 200
    gaps = gaps_res.json()
    assert len(gaps) >= 2
    assert all(g["status"] == "NOT_COLLECTED" for g in gaps)

    # Verify Report Export Completeness & Scrubbing
    report_res = client.get(f"/api/reports/{inv_id}/export")
    assert report_res.status_code == 200
    report = report_res.json()
    assert "report_metadata" in report
    assert "executive_summary" in report
    assert "score" in report["executive_summary"]
    assert "confidence" in report["executive_summary"]
    assert "reply_to" in report["executive_summary"]
    assert report["executive_summary"]["verdict"] in ("LIKELY_PHISHING", "SUSPICIOUS")
    
    assert "detector_hypotheses" in report
    assert "classified_evidence_items" in report
    assert "graph_relationships" in report
    assert "forensic_methodology_and_limitations" in report
    
    # Assert scrubbing: string representation shouldn't contain C:\\
    import json
    report_str = json.dumps(report)
    assert "C:\\" not in report_str
    assert "API_KEY" not in report_str.upper()


def test_upload_ambiguous_minimal_email():
    """Verify upload of ambiguous email without auth headers returns INCONCLUSIVE verdict."""
    file_path = FIXTURES_DIR / "minimal_no_auth.eml"
    with open(file_path, "rb") as f:
        response = client.post(
            "/api/investigations/upload",
            files={"file": ("minimal_no_auth.eml", f, "message/rfc822")},
            data={"title": "Ambiguous Minimal Test"}
        )

    assert response.status_code == 201
    data = response.json()
    assert data["verdict"] == "INCONCLUSIVE"
    assert data["parsed_metadata"]["detection_result"]["verdict"] == "INCONCLUSIVE"
    assert data["parsed_metadata"]["detection_result"]["confidence"] == "LOW"


def test_upload_rejection_non_eml_extension():
    """Verify rejection of files without .eml extension."""
    response = client.post(
        "/api/investigations/upload",
        files={"file": ("sample.pdf", b"%PDF-1.4...", "application/pdf")},
    )
    assert response.status_code == 400
    assert "Only .eml email files are supported" in response.json()["detail"]


def test_upload_rejection_empty_file():
    """Verify rejection of empty .eml files."""
    response = client.post(
        "/api/investigations/upload",
        files={"file": ("empty.eml", b"", "message/rfc822")},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_upload_rejection_oversized_file():
    """Verify rejection of files exceeding the 15 MB limit."""
    # 15 MB + 1 KB
    huge_bytes = b"X" * (15 * 1024 * 1024 + 1024)
    response = client.post(
        "/api/investigations/upload",
        files={"file": ("oversized.eml", huge_bytes, "message/rfc822")},
    )
    assert response.status_code == 413
    assert "exceeds" in response.json()["detail"].lower()


def test_list_and_delete_investigation():
    """Verify listing and safe deletion of an investigation case."""
    # Upload sample to delete
    file_path = FIXTURES_DIR / "minimal_no_auth.eml"
    with open(file_path, "rb") as f:
        res = client.post(
            "/api/investigations/upload",
            files={"file": ("to_delete.eml", f, "message/rfc822")},
            data={"title": "Delete Case Target"}
        )
    inv_id = res.json()["id"]

    # Verify present in list
    list_res = client.get("/api/investigations")
    assert list_res.status_code == 200
    ids = [i["id"] for i in list_res.json()]
    assert inv_id in ids

    # Search filter test
    filter_res = client.get("/api/investigations?query=Delete+Case")
    assert filter_res.status_code == 200
    assert any(i["id"] == inv_id for i in filter_res.json())

    # Delete case
    del_res = client.delete(f"/api/investigations/{inv_id}")
    assert del_res.status_code == 200
    assert del_res.json()["deleted"] is True

    assert client.get(f"/api/investigations/{inv_id}").status_code == 404

def test_html_script_injection_escaped():
    """Verify that script tags are stripped and escaped in safe text preview."""
    malicious_eml = b'''From: attacker@example.com
To: victim@example.com
Subject: Test Injection
Content-Type: text/html

<html><body>
<h1>Hello</h1>
<script>alert("XSS")</script>
<style>body { display: none; }</style>
</body></html>
'''
    response = client.post(
        "/api/investigations/upload",
        files={"file": ("injection.eml", malicious_eml, "message/rfc822")},
        data={"title": "Injection Test"}
    )
    assert response.status_code == 201
    data = response.json()
    safe_text = data["parsed_metadata"]["safe_body_text_preview"]
    assert "alert" not in safe_text
    assert "XSS" not in safe_text
    assert "display: none" not in safe_text
    assert "Hello" in safe_text


def test_intentional_404_preserved():
    """Verify that the global exception handler preserves intentional 404 errors."""
    response = client.get("/api/investigations/does-not-exist-uuid")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_unexpected_exception_sanitized():
    """Verify that unexpected exceptions return a safe 500 error."""
    # Monkeypatch a route to throw a raw exception
    @app.get("/api/test-error")
    def throw_error():
        raise RuntimeError("Secret absolute path C:/Windows/system32")
    
    response = client.get("/api/test-error")
    assert response.status_code == 500
    detail = response.json().get("detail", "")
    assert "internal server error" in detail.lower()
    assert "C:/Windows" not in detail
