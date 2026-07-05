import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from email.utils import parseaddr
from urllib.parse import urlsplit

from .config import settings
from .org_context import is_lookalike_domain

URL_PATTERN = re.compile(r"https?://[^\s<>'\"\])]+", re.IGNORECASE)
URGENCY_PATTERN = re.compile(
    r"\b(urgent|immediately|final warning|act now|within \d+ hours?|"
    r"account (?:locked|suspended)|verify now)\b",
    re.IGNORECASE,
)
CREDENTIAL_PATTERN = re.compile(
    r"\b(password|passcode|login|sign[ -]?in|credentials?|"
    r"verify your (?:account|identity)|one[- ]time code)\b",
    re.IGNORECASE,
)
PAYMENT_PATTERN = re.compile(
    r"\b(gift cards?|wire transfer|crypto(?:currency)?|bitcoin|bank details|"
    r"invoice attached|payment overdue)\b",
    re.IGNORECASE,
)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly"}
SUSPICIOUS_TLDS = {"zip", "mov", "click", "top", "xyz", "work", "support", "country"}
FREE_MAIL = {"gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "proton.me"}
BRANDS = {"microsoft", "google", "apple", "paypal", "amazon", "netflix", "docusign", "dropbox"}
ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u2060\ufeff]")


@dataclass(frozen=True)
class RuleFinding:
    id: str
    title: str
    detail: str
    severity: str
    weight: int
    evidence: str = ""
    kind: str = "language"


def _domain_from_sender(sender: str) -> str:
    address = parseaddr(sender)[1]
    match = re.search(r"@([A-Za-z0-9.-]+)", address)
    return match.group(1).lower().rstrip(".") if match else ""


def _header_findings(sender: str, headers: dict[str, str]) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    normalized = {key.lower(): value for key, value in headers.items()}
    auth = normalized.get("authentication-results", "").lower()
    spf = normalized.get("received-spf", "").lower()
    if any(token in auth for token in ("spf=fail", "dkim=fail", "dmarc=fail")) or spf.startswith("fail"):
        findings.append(
            RuleFinding(
                "authentication_failure",
                "Email authentication failed",
                "Trusted headers report an SPF, DKIM, or DMARC authentication failure.",
                "high",
                30,
                normalized.get("authentication-results") or normalized.get("received-spf", ""),
                "header",
            )
        )
    reply_to = normalized.get("reply-to", "")
    sender_domain = _domain_from_sender(sender)
    reply_domain = _domain_from_sender(reply_to)
    if reply_domain and sender_domain and reply_domain != sender_domain:
        findings.append(
            RuleFinding(
                "reply_to_mismatch",
                "Reply-to domain mismatch",
                "Replies are directed to a different domain than the visible sender.",
                "high",
                20,
                reply_to,
                "header",
            )
        )
    return findings


def _url_findings(text: str) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    for raw_url in URL_PATTERN.findall(text)[:20]:
        try:
            host = (urlsplit(raw_url).hostname or "").lower()
            if not host:
                continue
            suspicious_reason = ""
            if host in SHORTENERS:
                suspicious_reason = "The link uses a URL shortener that hides its destination."
            else:
                try:
                    ipaddress.ip_address(host)
                    suspicious_reason = "The link uses a raw IP address instead of a recognizable domain."
                except ValueError:
                    tld = host.rsplit(".", 1)[-1]
                    if tld in SUSPICIOUS_TLDS:
                        suspicious_reason = f"The link uses the frequently abused .{tld} top-level domain."
                    elif "xn--" in host:
                        suspicious_reason = (
                            "The link contains an internationalized domain that may imitate another name."
                        )
                    elif host.count(".") >= 4:
                        suspicious_reason = "The link has an unusually deep subdomain structure."
            if suspicious_reason:
                findings.append(
                    RuleFinding(
                        "suspicious_url", "Suspicious link", suspicious_reason, "high", 20, raw_url, "link"
                    )
                )
        except ValueError:
            continue
    return findings


def evaluate(
    sender: str,
    subject: str,
    body: str,
    headers: dict[str, str] | None = None,
) -> list[RuleFinding]:
    text = f"{subject}\n{body}"
    findings: list[RuleFinding] = []
    patterns = [
        (
            URGENCY_PATTERN,
            "urgency",
            "Pressure or urgency",
            "The message pressures the reader to act quickly.",
            "medium",
            14,
        ),
        (
            CREDENTIAL_PATTERN,
            "credentials",
            "Credential request",
            "The message refers to credentials, login, or identity verification.",
            "high",
            22,
        ),
        (
            PAYMENT_PATTERN,
            "payment",
            "Unusual payment language",
            "The message requests a risky or unusual form of payment.",
            "high",
            24,
        ),
    ]
    for pattern, rule_id, title, detail, severity, weight in patterns:
        match = pattern.search(text)
        if match:
            findings.append(RuleFinding(rule_id, title, detail, severity, weight, match.group(0)))

    sender_domain = _domain_from_sender(sender)
    sender_text = sender.lower()
    if sender_domain in FREE_MAIL and any(brand in sender_text for brand in BRANDS):
        findings.append(
            RuleFinding(
                "brand_freemail",
                "Brand sent from free email",
                "The display name mentions a well-known brand but the address uses a free mailbox provider.",
                "high",
                24,
                sender,
                "sender",
            )
        )
    if sender and not sender_domain:
        findings.append(
            RuleFinding(
                "malformed_sender",
                "Malformed sender",
                "The sender address could not be parsed reliably.",
                "medium",
                10,
                sender,
                "sender",
            )
        )
    if re.search(r"\b(dear (customer|user|member)|valued customer)\b", text, re.IGNORECASE):
        findings.append(
            RuleFinding(
                "generic_greeting",
                "Generic greeting",
                "The greeting is generic rather than personalized.",
                "low",
                6,
                "generic greeting",
            )
        )
    if body.count("!") >= 4 or re.search(r"\b[A-Z]{8,}\b", body):
        findings.append(
            RuleFinding(
                "aggressive_style",
                "Aggressive formatting",
                "Excessive capitals or exclamation marks increase social-engineering risk.",
                "low",
                7,
            )
        )
    normalized_text = unicodedata.normalize("NFKC", text)
    if ZERO_WIDTH.search(text) or normalized_text != text:
        findings.append(
            RuleFinding(
                "unicode_obfuscation",
                "Unicode obfuscation",
                "Invisible or compatibility Unicode characters may be hiding suspicious wording.",
                "medium",
                12,
                "",
                "language",
            )
        )
    lookalike = is_lookalike_domain(
        sender_domain,
        settings.trusted_domain_list,
        settings.protected_brand_list,
    )
    if lookalike:
        findings.append(
            RuleFinding(
                "lookalike_domain",
                "Possible lookalike domain",
                f"The sender domain resembles '{lookalike}' but does not exactly match a trusted domain.",
                "high",
                28,
                sender_domain,
                "sender",
            )
        )
    if headers:
        findings.extend(_header_findings(sender, headers))
    findings.extend(_url_findings(text))

    deduplicated: dict[str, RuleFinding] = {}
    for finding in findings:
        deduplicated.setdefault(finding.id, finding)
    return list(deduplicated.values())
