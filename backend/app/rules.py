import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

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
    match = re.search(r"@([A-Za-z0-9.-]+)", sender)
    return match.group(1).lower().rstrip(".") if match else ""


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


def evaluate(sender: str, subject: str, body: str) -> list[RuleFinding]:
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
    findings.extend(_url_findings(text))

    deduplicated: dict[str, RuleFinding] = {}
    for finding in findings:
        deduplicated.setdefault(finding.id, finding)
    return list(deduplicated.values())
