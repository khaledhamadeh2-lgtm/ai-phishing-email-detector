from unittest.mock import patch

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


def test_eml_upload_reports_static_attachment_risk() -> None:
    eml = (
        b"From: sender@example.org\r\n"
        b"Subject: Report\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=abc\r\n\r\n"
        b"--abc\r\nContent-Type: text/plain\r\n\r\nPlease review.\r\n"
        b"--abc\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="invoice.pdf.exe"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"TVqQAAMAAAAEAAAA\r\n"
        b"--abc--\r\n"
    )
    response = client.post("/api/analyze-eml", files={"file": ("sample.eml", eml, "message/rfc822")})
    assert response.status_code == 200
    data = response.json()
    assert data["attachments"][0]["risk_level"] == "high"
    assert data["attachments"][0]["score"] > 0


def test_security_headers() -> None:
    response = client.get("/api/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_feedback_records_without_email_body(tmp_path) -> None:
    feedback_file = tmp_path / "feedback.jsonl"
    with patch("app.main.settings.feedback_path", str(feedback_file)):
        response = client.post(
            "/api/feedback",
            json={"analysis_id": "abc123def456", "label": "false_positive", "note": "Known vendor email."},
        )
    assert response.status_code == 200
    saved = feedback_file.read_text(encoding="utf-8")
    assert "false_positive" in saved
    assert "Known vendor email" in saved
    assert "body" not in saved


def test_mailbox_history_endpoint_returns_redacted_records() -> None:
    with patch("app.main.read_mailbox_history") as history:
        history.return_value = [
            {
                "uid": "7",
                "fingerprint": "abc",
                "analysis_id": "abc123def456",
                "scanned_at": "2026-06-25T10:00:00+00:00",
                "sender": "sender@example.org",
                "subject": "Invoice",
                "probability": 72.5,
                "verdict": "Likely Phishing",
                "risk_factors": ["Credential request"],
                "attachment_count": 0,
            }
        ]
        response = client.get("/api/mailbox/history?limit=10")

    assert response.status_code == 200
    data = response.json()
    assert data[0]["analysis_id"] == "abc123def456"
    assert "body" not in data[0]
