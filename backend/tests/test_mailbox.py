import json
from pathlib import Path
from unittest.mock import patch

from app.config import settings
from app.mailbox import read_mailbox_history, scan_mailbox_once

PHISHING_EML = (
    b"From: Microsoft Support <security.microsoft@gmail.com>\r\n"
    b"Reply-To: collector@other-example.net\r\n"
    b"Authentication-Results: mx.example; spf=fail dkim=fail dmarc=fail\r\n"
    b"Subject: URGENT account suspended\r\n\r\n"
    b"Verify your password immediately at https://198.51.100.10/login!!!!"
)


class FakeImap:
    def __init__(self, *args, **kwargs) -> None:
        self.fetches = 0

    def __enter__(self):
        return self

    def __exit__(self, *args) -> None:
        return None

    def login(self, username: str, password: str):
        return "OK", []

    def select(self, folder: str, readonly: bool = False):
        assert readonly is True
        return "OK", []

    def uid(self, command: str, *args):
        if command == "search":
            return "OK", [b"42"]
        self.fetches += 1
        assert args == ("42", f"(BODY.PEEK[]<0.{settings.max_email_bytes + 1}>)")
        return "OK", [(b"42 (BODY[])", PHISHING_EML)]


def test_read_only_mailbox_scan_writes_redacted_alert(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    alerts = tmp_path / "alerts.jsonl"
    history = tmp_path / "history.jsonl"
    with (
        patch("app.mailbox.imaplib.IMAP4_SSL", FakeImap),
        patch.object(settings, "mailbox_host", "imap.example.com"),
        patch.object(settings, "mailbox_username", "analyst@example.com"),
        patch.object(settings, "mailbox_password", "app-password"),
        patch.object(settings, "mailbox_state_path", str(state)),
        patch.object(settings, "mailbox_alert_path", str(alerts)),
        patch.object(settings, "mailbox_history_path", str(history)),
    ):
        result = scan_mailbox_once()

    assert len(result) == 1
    stored = json.loads(alerts.read_text(encoding="utf-8"))
    assert stored["uid"] == "42"
    assert "body" not in stored
    history_row = json.loads(history.read_text(encoding="utf-8"))
    assert history_row["analysis_id"]
    assert history_row["verdict"] == "Likely Phishing"
    assert "body" not in history_row
    assert state.exists()


def test_mailbox_history_reader_returns_recent_redacted_records(tmp_path: Path) -> None:
    history = tmp_path / "history.jsonl"
    history.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "uid": "1",
                        "fingerprint": "abc",
                        "analysis_id": "abc123def456",
                        "scanned_at": "2026-06-25T10:00:00+00:00",
                        "sender": "sender@example.org",
                        "subject": "Normal update",
                        "probability": 12.0,
                        "verdict": "Safe",
                        "risk_factors": [],
                        "attachment_count": 0,
                    }
                ),
                json.dumps(
                    {
                        "uid": "2",
                        "fingerprint": "def",
                        "analysis_id": "def123abc456",
                        "scanned_at": "2026-06-25T10:05:00+00:00",
                        "sender": "billing@example.org",
                        "subject": "Urgent invoice",
                        "probability": 81.2,
                        "verdict": "Likely Phishing",
                        "risk_factors": ["Pressure or urgency"],
                        "attachment_count": 1,
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )
    with patch.object(settings, "mailbox_history_path", str(history)):
        records = read_mailbox_history(limit=1)

    assert len(records) == 1
    assert records[0].uid == "2"
    assert records[0].risk_factors == ["Pressure or urgency"]
