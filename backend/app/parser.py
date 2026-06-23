from email import policy
from email.parser import BytesParser


def parse_eml(content: bytes) -> tuple[str, str, str]:
    """Parse text from an EML without opening attachments or resolving URLs."""
    message = BytesParser(policy=policy.default).parsebytes(content)
    sender = str(message.get("from", ""))
    subject = str(message.get("subject", ""))
    body_parts: list[str] = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() == "text/plain":
                try:
                    body_parts.append(part.get_content())
                except (LookupError, UnicodeDecodeError):
                    payload = part.get_payload(decode=True) or b""
                    body_parts.append(payload.decode("utf-8", errors="replace"))
    else:
        try:
            body_parts.append(message.get_content())
        except (LookupError, UnicodeDecodeError):
            payload = message.get_payload(decode=True) or b""
            body_parts.append(payload.decode("utf-8", errors="replace"))

    body = "\n".join(body_parts).strip()
    if not body:
        raise ValueError("The EML file contains no readable plain-text message body.")
    return sender, subject, body
