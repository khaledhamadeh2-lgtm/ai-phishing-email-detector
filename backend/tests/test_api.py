from unittest.mock import patch

from fastapi.testclient import TestClient

from app.config import settings
from app.main import _RATE_LIMIT_BUCKETS, app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_validation() -> None:
    response = client.post("/api/analyze", json={"body": ""})
    assert response.status_code == 422


def test_analyze_accepts_per_request_tuning_context() -> None:
    response = client.post(
        "/api/analyze",
        json={
            "sender": "Maya <maya@example.org>",
            "subject": "Normal update",
            "body": "The project notes are ready in the usual workspace.",
            "trusted_domains": ["example.org"],
            "sensitivity": "precision",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["sensitivity"] == "precision"
    assert data["suspicious_threshold"] > 35
    assert data["trust_signals"]


def test_analyze_persists_redacted_scan_history_by_org(tmp_path) -> None:
    database = tmp_path / "history.sqlite3"
    _RATE_LIMIT_BUCKETS.clear()
    with (
        patch("app.storage.settings.database_path", str(database)),
        patch("app.storage.settings.database_enabled", True),
        patch("app.storage.settings.store_email_bodies", False),
        patch("app.main.settings.database_path", str(database)),
    ):
        response = client.post(
            "/api/analyze",
            headers={"X-Org-ID": "acme", "X-User-ID": "analyst-1"},
            json={
                "sender": "Maya <maya@example.org>",
                "subject": "Normal update",
                "body": "Private text should be hashed, not stored in history.",
            },
        )
        history = client.get("/api/scans/history?limit=5", headers={"X-Org-ID": "acme"})
        other_history = client.get("/api/scans/history?limit=5", headers={"X-Org-ID": "other"})

    assert response.status_code == 200
    assert history.status_code == 200
    data = history.json()
    assert len(data) == 1
    assert data[0]["org_id"] == "acme"
    assert data[0]["body_sha256"]
    assert "body" not in data[0]
    assert other_history.json() == []


def test_current_user_settings_metrics_and_threat_intel(tmp_path) -> None:
    database = tmp_path / "product.sqlite3"
    _RATE_LIMIT_BUCKETS.clear()
    headers = {"X-Org-ID": "acme", "X-User-ID": "analyst-1"}
    with (
        patch("app.storage.settings.database_path", str(database)),
        patch("app.storage.settings.database_enabled", True),
        patch("app.storage.settings.store_email_bodies", False),
    ):
        me = client.get("/api/me", headers=headers)
        settings_response = client.put(
            "/api/org/settings",
            headers=headers,
            json={
                "org_id": "ignored-client-org",
                "trusted_domains": ["example.org"],
                "trusted_senders": ["maya@example.org"],
                "sensitivity": "precision",
                "scan_retention_days": 45,
                "store_email_bodies": False,
                "mailbox_alert_threshold": 80,
            },
        )
        client.post(
            "/api/analyze",
            headers=headers,
            json={
                "sender": "Maya <maya@example.org>",
                "subject": "Normal update",
                "body": "Notes live at https://example.org/notes.",
            },
        )
        metrics = client.get("/api/dashboard/metrics", headers=headers)
        intel = client.post(
            "/api/threat-intel/preview",
            headers=headers,
            json={
                "sender": "Maya <maya@example.org>",
                "subject": "Normal update",
                "body": "Notes live at https://example.org/notes.",
            },
        )

    assert me.status_code == 200
    assert me.json()["auth_mode"] == "demo-headers"
    assert settings_response.status_code == 200
    assert settings_response.json()["org_id"] == "acme"
    assert settings_response.json()["trusted_domains"] == ["example.org"]
    assert metrics.status_code == 200
    assert metrics.json()["total_scans"] == 1
    assert intel.status_code == 200
    assert intel.json()["domains"] == ["example.org"]
    assert intel.json()["enabled"] is False


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


def test_api_rate_limit_returns_clean_error() -> None:
    _RATE_LIMIT_BUCKETS.clear()
    with (
        patch.object(settings, "rate_limit_requests", 1),
        patch.object(settings, "rate_limit_window_seconds", 60),
    ):
        first = client.post("/api/analyze", json={"body": "hello"})
        second = client.post("/api/analyze", json={"body": "hello again"})

    _RATE_LIMIT_BUCKETS.clear()
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["detail"] == "Too many requests. Please wait and retry."


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
