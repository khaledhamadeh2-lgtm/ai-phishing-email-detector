from dataclasses import dataclass
from email import policy
from email.parser import BytesParser

from .attachments import AttachmentRisk, analyze_attachment
from .config import settings

MAX_MIME_PARTS = 100
MAX_TEXT_PART_BYTES = 100_000
SECURITY_HEADERS = (
    "authentication-results",
    "received-spf",
    "reply-to",
    "return-path",
    "message-id",
    "from",
    "to",
    "date",
)


@dataclass(frozen=True)
class ParsedEmail:
    sender: str
    subject: str
    body: str
    headers: dict[str, str]
    attachments: tuple[AttachmentRisk, ...]


def _safe_part_text(part) -> str:
    payload = part.get_payload(decode=True)
    if payload is not None:
        return payload[:MAX_TEXT_PART_BYTES].decode(part.get_content_charset() or "utf-8", errors="replace")
    content = part.get_content()
    return str(content)[:MAX_TEXT_PART_BYTES]


def parse_eml(content: bytes) -> ParsedEmail:
    """Parse text from an EML without opening attachments or resolving URLs."""
    message = BytesParser(policy=policy.default).parsebytes(content)
    sender = str(message.get("from", ""))
    subject = str(message.get("subject", ""))
    headers = {name: str(message.get(name, ""))[:2_000] for name in SECURITY_HEADERS}
    body_parts: list[str] = []
    attachments: list[AttachmentRisk] = []

    if message.is_multipart():
        for index, part in enumerate(message.walk()):
            if index >= MAX_MIME_PARTS:
                break
            if part.get_content_disposition() == "attachment":
                payload = part.get_payload(decode=True) or b""
                attachments.append(
                    analyze_attachment(
                        part.get_filename() or "attachment",
                        part.get_content_type(),
                        payload,
                        settings.max_attachment_bytes,
                    )
                )
                continue
            if part.get_content_type() == "text/plain":
                try:
                    body_parts.append(_safe_part_text(part))
                except (LookupError, UnicodeDecodeError):
                    payload = part.get_payload(decode=True) or b""
                    body_parts.append(payload[:MAX_TEXT_PART_BYTES].decode("utf-8", errors="replace"))
    else:
        try:
            body_parts.append(_safe_part_text(message))
        except (LookupError, UnicodeDecodeError):
            payload = message.get_payload(decode=True) or b""
            body_parts.append(payload[:MAX_TEXT_PART_BYTES].decode("utf-8", errors="replace"))

    body = "\n".join(body_parts).strip()
    if not body:
        raise ValueError("The EML file contains no readable plain-text message body.")
    return ParsedEmail(
        sender=sender, subject=subject, body=body, headers=headers, attachments=tuple(attachments)
    )
