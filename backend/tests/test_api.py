from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_validation() -> None:
    response = client.post("/api/analyze", json={"body": ""})
    assert response.status_code == 422


def test_eml_upload() -> None:
    eml = b"From: sender@example.org\r\nSubject: Hello\r\n\r\nA normal plain text message."
    response = client.post("/api/analyze-eml", files={"file": ("sample.eml", eml, "message/rfc822")})
    assert response.status_code == 200
    assert "probability" in response.json()
