from unittest.mock import patch

from app.mailbox import MailboxAlert
from app.worker import run


def test_worker_can_run_one_bounded_cycle() -> None:
    alert = MailboxAlert(
        uid="7",
        fingerprint="abc",
        sender="sender@example.com",
        subject="Suspicious",
        probability=91.0,
        verdict="Likely Phishing",
        risk_factors=["Credential request"],
    )
    with patch("app.worker.scan_mailbox_once", return_value=[alert]) as scan:
        run(max_cycles=1)
    scan.assert_called_once_with()


def test_worker_fails_closed_and_continues() -> None:
    with patch("app.worker.scan_mailbox_once", side_effect=RuntimeError("safe failure")):
        run(max_cycles=1)
