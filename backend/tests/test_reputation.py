from fastapi.testclient import TestClient
from backend.app.main import app
from unittest.mock import patch, MagicMock
import httpx

client = TestClient(app)

def test_reputation_malformed_address():
    response = client.post("/api/reputation/check", json={"email": "not-an-email", "consent_given": True})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "INCONCLUSIVE"
    assert data["syntax"]["is_valid_format"] is False
    assert "Invalid email address format" in data["syntax"]["error"]

def test_reputation_no_consent():
    response = client.post("/api/reputation/check", json={"email": "user@example.com", "consent_given": False})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "INCONCLUSIVE"
    assert data["syntax"]["is_valid_format"] is True
    assert "user consent" in data["explanation"].lower()

def test_reputation_unconfigured_provider(monkeypatch):
    from backend.app.routes import reputation
    from backend.app.analyzer.reputation import EmailReputationChecker
    
    # Force unconfigured state
    reputation.checker = EmailReputationChecker(provider_name="none", api_key=None)
    
    response = client.post("/api/reputation/check", json={"email": "valid@example.com", "consent_given": True})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "INCONCLUSIVE"
    assert data["syntax"]["is_valid_format"] is True
    assert "EmailRep provider is not configured" in data["explanation"]


# Mocked HTTP Tests
def _setup_mock_checker():
    from backend.app.analyzer.reputation import EmailReputationChecker
    return EmailReputationChecker(provider_name="emailrep", api_key="secret")

@patch("backend.app.analyzer.reputation.httpx.Client")
def test_reputation_mock_suspicious(mock_httpx_client, monkeypatch):
    from backend.app.routes import reputation
    reputation.checker = _setup_mock_checker()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "email": "malicious@badactor.com",
        "reputation": "low",
        "suspicious": True,
        "references": 5,
        "details": {
            "blacklisted": True,
            "malicious_activity": True
        }
    }
    
    # Setup mock context manager
    mock_client_instance = MagicMock()
    mock_client_instance.get.return_value = mock_response
    mock_httpx_client.return_value.__enter__.return_value = mock_client_instance

    response = client.post("/api/reputation/check", json={"email": "malicious@badactor.com", "consent_given": True})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "REPORTED_SUSPICIOUS"
    assert data["confidence"] == "HIGH"  # because references > 0
    assert len(data["findings"]) >= 2
    assert "EmailRep.io" in data["sources_checked"]

@patch("backend.app.analyzer.reputation.httpx.Client")
def test_reputation_mock_high_reputation(mock_httpx_client, monkeypatch):
    from backend.app.routes import reputation
    reputation.checker = _setup_mock_checker()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "email": "gooduser@example.com",
        "reputation": "high",
        "suspicious": False,
        "references": 0,
        "details": {
            "blacklisted": False,
            "malicious_activity": False
        }
    }
    
    mock_client_instance = MagicMock()
    mock_client_instance.get.return_value = mock_response
    mock_httpx_client.return_value.__enter__.return_value = mock_client_instance
    
    response = client.post("/api/reputation/check", json={"email": "gooduser@example.com", "consent_given": True})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "NO_REPORTS_FOUND"
    assert data["confidence"] == "LOW"

@patch("backend.app.analyzer.reputation.httpx.Client")
def test_reputation_mock_no_data(mock_httpx_client, monkeypatch):
    from backend.app.routes import reputation
    reputation.checker = _setup_mock_checker()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "email": "unknown@example.com",
        "reputation": "none",
        "suspicious": False,
        "references": 0,
        "details": {}
    }
    
    mock_client_instance = MagicMock()
    mock_client_instance.get.return_value = mock_response
    mock_httpx_client.return_value.__enter__.return_value = mock_client_instance
    
    response = client.post("/api/reputation/check", json={"email": "unknown@example.com", "consent_given": True})
    assert response.status_code == 200
    data = response.json()
    # "none" reputation + suspicious=False falls to INCONCLUSIVE in our logic
    assert data["verdict"] == "INCONCLUSIVE"
    assert data["confidence"] == "LOW"

@patch("backend.app.analyzer.reputation.httpx.Client")
def test_reputation_mock_timeout(mock_httpx_client, monkeypatch):
    from backend.app.routes import reputation
    reputation.checker = _setup_mock_checker()

    mock_client_instance = MagicMock()
    mock_client_instance.get.side_effect = httpx.TimeoutException("Timeout")
    mock_httpx_client.return_value.__enter__.return_value = mock_client_instance
    
    response = client.post("/api/reputation/check", json={"email": "timeout@example.com", "consent_given": True})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "INCONCLUSIVE"
    assert "timed out" in data["explanation"].lower()

@patch("backend.app.analyzer.reputation.httpx.Client")
def test_reputation_mock_rate_limit(mock_httpx_client, monkeypatch):
    from backend.app.routes import reputation
    reputation.checker = _setup_mock_checker()

    mock_response = MagicMock()
    mock_response.status_code = 429
    
    mock_client_instance = MagicMock()
    mock_client_instance.get.return_value = mock_response
    mock_httpx_client.return_value.__enter__.return_value = mock_client_instance
    
    response = client.post("/api/reputation/check", json={"email": "ratelimit@example.com", "consent_given": True})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "INCONCLUSIVE"
    assert "rate limit exceeded" in data["explanation"].lower()

@patch("backend.app.analyzer.reputation.httpx.Client")
def test_reputation_mock_invalid_key(mock_httpx_client, monkeypatch):
    from backend.app.routes import reputation
    reputation.checker = _setup_mock_checker()

    mock_response = MagicMock()
    mock_response.status_code = 401
    
    mock_client_instance = MagicMock()
    mock_client_instance.get.return_value = mock_response
    mock_httpx_client.return_value.__enter__.return_value = mock_client_instance
    
    response = client.post("/api/reputation/check", json={"email": "invalidkey@example.com", "consent_given": True})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "INCONCLUSIVE"
    assert "invalid or unauthorized api key" in data["explanation"].lower()

@patch("backend.app.analyzer.reputation.httpx.Client")
def test_reputation_mock_malformed_response(mock_httpx_client, monkeypatch):
    from backend.app.routes import reputation
    reputation.checker = _setup_mock_checker()

    mock_client_instance = MagicMock()
    # simulating an exception inside json() or request handling
    mock_client_instance.get.side_effect = Exception("JSON Decode Error")
    mock_httpx_client.return_value.__enter__.return_value = mock_client_instance
    
    response = client.post("/api/reputation/check", json={"email": "malformed@example.com", "consent_given": True})
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "INCONCLUSIVE"
    assert "unexpected error occurred" in data["explanation"].lower()
