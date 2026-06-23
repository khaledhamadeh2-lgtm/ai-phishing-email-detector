import hashlib
import imaplib
import json
import logging
import ssl
from dataclasses import asdict, dataclass
from pathlib import Path

from .config import settings
from .detector import analyze
from .parser import parse_eml

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MailboxAlert:
    uid: str
    fingerprint: str
    sender: str
    subject: str
    probability: float
    verdict: str
    risk_factors: list[str]


def _load_seen(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return set(data.get("fingerprints", []))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return set()


def _save_seen(path: Path, seen: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"fingerprints": sorted(seen)[-10_000:]}), encoding="utf-8")
    temporary.replace(path)


def _authenticate(client: imaplib.IMAP4_SSL) -> None:
    if settings.mailbox_oauth2_token:
        auth = f"user={settings.mailbox_username}\1auth=Bearer {settings.mailbox_oauth2_token}\1\1"
        client.authenticate("XOAUTH2", lambda _: auth.encode())
    elif settings.mailbox_password:
        client.login(settings.mailbox_username, settings.mailbox_password)
    else:
        raise RuntimeError("Configure an IMAP app password or OAuth2 access token.")


def scan_mailbox_once() -> list[MailboxAlert]:
    if not settings.mailbox_host or not settings.mailbox_username:
        raise RuntimeError("Mailbox host and username are required.")
    context = ssl.create_default_context()
    state_path = Path(settings.mailbox_state_path)
    alert_path = Path(settings.mailbox_alert_path)
    seen = _load_seen(state_path)
    alerts: list[MailboxAlert] = []

    with imaplib.IMAP4_SSL(
        settings.mailbox_host,
        settings.mailbox_port,
        ssl_context=context,
        timeout=30,
    ) as client:
        _authenticate(client)
        status, _ = client.select(settings.mailbox_folder, readonly=True)
        if status != "OK":
            raise RuntimeError("The configured mailbox folder could not be opened read-only.")
        status, search_data = client.uid("search", None, "UNSEEN")
        if status != "OK":
            raise RuntimeError("Mailbox search failed.")
        uids = search_data[0].split()[-settings.mailbox_max_messages :]
        for uid_bytes in uids:
            uid = uid_bytes.decode("ascii", errors="ignore")
            fetch_item = f"(BODY.PEEK[]<0.{settings.max_email_bytes + 1}>)"
            status, message_data = client.uid("fetch", uid, fetch_item)
            if status != "OK":
                logger.warning("Skipping UID %s because the message could not be fetched.", uid)
                continue
            raw = next(
                (item[1] for item in message_data if isinstance(item, tuple) and isinstance(item[1], bytes)),
                b"",
            )
            if not raw or len(raw) > settings.max_email_bytes:
                continue
            fingerprint = hashlib.sha256(raw).hexdigest()
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            try:
                parsed = parse_eml(raw)
            except ValueError:
                continue
            result = analyze(parsed.sender, parsed.subject, parsed.body, parsed.headers)
            if result.probability >= settings.mailbox_alert_threshold:
                alerts.append(
                    MailboxAlert(
                        uid=uid,
                        fingerprint=fingerprint,
                        sender=parsed.sender[:500],
                        subject=parsed.subject[:1_000],
                        probability=result.probability,
                        verdict=result.verdict,
                        risk_factors=[factor.title for factor in result.risk_factors],
                    )
                )

    _save_seen(state_path, seen)
    if alerts:
        alert_path.parent.mkdir(parents=True, exist_ok=True)
        with alert_path.open("a", encoding="utf-8") as handle:
            for alert in alerts:
                handle.write(json.dumps(asdict(alert)) + "\n")
    return alerts
