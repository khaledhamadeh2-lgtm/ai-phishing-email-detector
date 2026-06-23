import json
from pathlib import Path
from unittest.mock import patch

from app.config import settings
from app.mailbox import scan_mailbox_once

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
    with (
        patch("app.mailbox.imaplib.IMAP4_SSL", FakeImap),
        patch.object(settings, "mailbox_host", "imap.example.com"),
        patch.object(settings, "mailbox_username", "analyst@example.com"),
        patch.object(settings, "mailbox_password", "app-password"),
        patch.object(settings, "mailbox_state_path", str(state)),
        patch.object(settings, "mailbox_alert_path", str(alerts)),
    ):
        result = scan_mailbox_once()

    assert len(result) == 1
    stored = json.loads(alerts.read_text(encoding="utf-8"))
    assert stored["uid"] == "42"
    assert "body" not in stored
    assert state.exists()
