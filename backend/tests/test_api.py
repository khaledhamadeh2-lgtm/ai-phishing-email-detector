import urllib.parse
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
    assert me.json()["auth_mode"] == "local"
    assert settings_response.status_code == 200
    assert settings_response.json()["org_id"] == "acme"
    assert settings_response.json()["trusted_domains"] == ["example.org"]
    assert metrics.status_code == 200
    assert metrics.json()["total_scans"] == 1
    assert intel.status_code == 200
    assert intel.json()["domains"] == ["example.org"]
    assert intel.json()["enabled"] is False


def test_signup_login_bearer_auth_and_organization_scope(tmp_path) -> None:
    database = tmp_path / "auth.sqlite3"
    _RATE_LIMIT_BUCKETS.clear()
    with (
        patch("app.storage.settings.database_path", str(database)),
        patch("app.storage.settings.database_enabled", True),
        patch("app.auth.settings.auth_secret_key", "test-secret"),
    ):
        signup = client.post(
            "/api/auth/signup",
            json={
                "email": "owner@acme.test",
                "password": "correct horse battery staple",
                "organization_name": "Acme Security",
            },
        )
        duplicate = client.post(
            "/api/auth/signup",
            json={
                "email": "OWNER@ACME.TEST",
                "password": "correct horse battery staple",
                "organization_name": "Acme Security",
            },
        )
        login = client.post(
            "/api/auth/login",
            json={"email": "owner@acme.test", "password": "correct horse battery staple"},
        )
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        me = client.get("/api/me", headers=headers)
        org = client.get("/api/org", headers=headers)
        analysis = client.post("/api/analyze", headers=headers, json={"body": "Normal update."})
        history = client.get("/api/scans/history", headers=headers)

    assert signup.status_code == 200
    assert signup.json()["user"]["role"] == "owner"
    assert duplicate.status_code == 409
    assert login.status_code == 200
    assert me.json()["email"] == "owner@acme.test"
    assert org.json()["name"] == "Acme Security"
    assert org.json()["members"][0]["email"] == "owner@acme.test"
    assert analysis.status_code == 200
    assert history.json()[0]["org_id"] == me.json()["org_id"]


def test_login_rejects_wrong_password(tmp_path) -> None:
    database = tmp_path / "auth-fail.sqlite3"
    _RATE_LIMIT_BUCKETS.clear()
    with (
        patch("app.storage.settings.database_path", str(database)),
        patch("app.storage.settings.database_enabled", True),
    ):
        client.post(
            "/api/auth/signup",
            json={
                "email": "owner@example.test",
                "password": "correct horse battery staple",
                "organization_name": "Example",
            },
        )
        response = client.post(
            "/api/auth/login",
            json={"email": "owner@example.test", "password": "wrong password"},
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


def test_gmail_oauth_connect_callback_and_disconnect(tmp_path) -> None:
    database = tmp_path / "oauth.sqlite3"
    _RATE_LIMIT_BUCKETS.clear()
    with (
        patch("app.storage.settings.database_path", str(database)),
        patch("app.storage.settings.database_enabled", True),
        patch("app.auth.settings.auth_secret_key", "test-secret"),
        patch("app.oauth.settings.public_base_url", "https://api.example.test"),
        patch("app.oauth.settings.gmail_oauth_client_id", "gmail-client-id"),
    ):
        signup = client.post(
            "/api/auth/signup",
            json={
                "email": "owner@acme.test",
                "password": "correct horse battery staple",
                "organization_name": "Acme Security",
            },
        )
        headers = {"Authorization": f"Bearer {signup.json()['access_token']}"}
        connect = client.get("/api/oauth/gmail/connect", headers=headers)
        state = connect.json()["state"]
        callback = client.post(
            "/api/oauth/callback",
            headers=headers,
            json={"provider": "gmail", "state": state, "code": "provider-auth-code"},
        )
        integrations = client.get("/api/oauth/integrations", headers=headers)
        disconnected = client.delete("/api/oauth/gmail", headers=headers)
        integrations_after = client.get("/api/oauth/integrations", headers=headers)

    assert connect.status_code == 200
    parsed_url = urllib.parse.urlparse(connect.json()["authorization_url"])
    query = urllib.parse.parse_qs(parsed_url.query)
    assert parsed_url.hostname == "accounts.google.com"
    assert query["scope"] == ["https://www.googleapis.com/auth/gmail.readonly"]
    assert callback.status_code == 200
    assert callback.json()["provider"] == "gmail"
    assert callback.json()["status"] == "connected_pending_token_exchange"
    assert integrations.json()[0]["connected"] is True
    assert disconnected.json() == {"status": "disconnected", "provider": "gmail"}
    assert integrations_after.json() == []


def test_oauth_callback_rejects_invalid_state(tmp_path) -> None:
    database = tmp_path / "oauth-invalid.sqlite3"
    _RATE_LIMIT_BUCKETS.clear()
    with (
        patch("app.storage.settings.database_path", str(database)),
        patch("app.storage.settings.database_enabled", True),
    ):
        response = client.post(
            "/api/oauth/callback",
            json={"provider": "outlook", "state": "invalid-state-value", "code": "provider-auth-code"},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "OAuth state is invalid or expired."


def test_subscription_usage_audit_and_compliance_controls(tmp_path) -> None:
    database = tmp_path / "saas.sqlite3"
    _RATE_LIMIT_BUCKETS.clear()
    headers = {"X-Org-ID": "acme", "X-User-ID": "owner-1"}
    with (
        patch("app.storage.settings.database_path", str(database)),
        patch("app.storage.settings.database_enabled", True),
        patch("app.storage.settings.enforce_plan_limits", False),
    ):
        subscription = client.put(
            "/api/billing/subscription",
            headers=headers,
            json={
                "org_id": "client-supplied-is-ignored",
                "plan": "team",
                "monthly_scan_limit": 5000,
                "mailbox_accounts_limit": 5,
                "retention_days_limit": 90,
                "threat_intel_enabled": False,
                "audit_log_enabled": True,
                "billing_status": "trial",
            },
        )
        client.post(
            "/api/analyze",
            headers=headers,
            json={
                "sender": "Security <security@example.org>",
                "subject": "Review",
                "body": "Please review the normal security notes.",
            },
        )
        usage = client.get("/api/billing/usage", headers=headers)
        audit = client.get("/api/audit/events?limit=10", headers=headers)
        posture = client.get("/api/security/posture", headers=headers)
        exported = client.get("/api/compliance/export", headers=headers)
        deleted = client.request(
            "DELETE",
            "/api/compliance/data",
            headers=headers,
            json={"confirm_org_id": "acme", "include_feedback": True, "include_audit_logs": False},
        )
        history_after_delete = client.get("/api/scans/history", headers=headers)

    assert subscription.status_code == 200
    assert subscription.json()["org_id"] == "acme"
    assert subscription.json()["plan"] == "team"
    assert usage.status_code == 200
    assert usage.json()["scans_used"] == 1
    assert usage.json()["monthly_scan_limit"] == 5000
    assert audit.status_code == 200
    assert any(event["action"] == "scan.created" for event in audit.json())
    assert posture.status_code == 200
    assert posture.json()["database_enabled"] is True
    assert exported.status_code == 200
    assert exported.json()["scans"][0]["org_id"] == "acme"
    assert "Full email bodies are excluded" in exported.json()["privacy_note"]
    assert deleted.status_code == 200
    assert deleted.json()["deleted_scans"] == 1
    assert history_after_delete.json() == []


def test_plan_limit_can_block_new_scans(tmp_path) -> None:
    database = tmp_path / "limits.sqlite3"
    _RATE_LIMIT_BUCKETS.clear()
    headers = {"X-Org-ID": "acme", "X-User-ID": "owner-1"}
    with (
        patch("app.storage.settings.database_path", str(database)),
        patch("app.storage.settings.database_enabled", True),
        patch("app.storage.settings.enforce_plan_limits", True),
    ):
        client.put(
            "/api/billing/subscription",
            headers=headers,
            json={
                "org_id": "acme",
                "plan": "starter",
                "monthly_scan_limit": 1,
                "mailbox_accounts_limit": 1,
                "retention_days_limit": 30,
                "threat_intel_enabled": False,
                "audit_log_enabled": True,
                "billing_status": "trial",
            },
        )
        first = client.post("/api/analyze", headers=headers, json={"body": "normal message"})
        second = client.post("/api/analyze", headers=headers, json={"body": "another message"})

    assert first.status_code == 200
    assert second.status_code == 402
    assert second.json()["detail"] == "Monthly scan limit reached for this workspace."


def test_compliance_delete_requires_matching_org_confirmation(tmp_path) -> None:
    database = tmp_path / "delete-confirm.sqlite3"
    _RATE_LIMIT_BUCKETS.clear()
    with (
        patch("app.storage.settings.database_path", str(database)),
        patch("app.storage.settings.database_enabled", True),
    ):
        response = client.request(
            "DELETE",
            "/api/compliance/data",
            headers={"X-Org-ID": "acme"},
            json={"confirm_org_id": "other", "include_feedback": True, "include_audit_logs": False},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Confirmation org ID does not match this workspace."


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
