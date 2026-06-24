from dataclasses import dataclass
from difflib import SequenceMatcher
from email.utils import parseaddr


@dataclass(frozen=True)
class TrustSignalResult:
    title: str
    detail: str
    adjustment: int


def domain_from_sender(sender: str) -> str:
    address = parseaddr(sender)[1]
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].lower().rstrip(".")


def _address_from_sender(sender: str) -> str:
    return parseaddr(sender)[1].lower()


def _registered_like_domain(domain: str) -> str:
    parts = domain.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def _skeleton(value: str) -> str:
    return (
        value.lower()
        .replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("4", "a")
        .replace("5", "s")
        .replace("@", "a")
        .replace("$", "s")
    )


def is_lookalike_domain(domain: str, trusted_domains: list[str], protected_brands: list[str]) -> str:
    if not domain:
        return ""
    base = _registered_like_domain(domain).split(".", 1)[0]
    base_skeleton = _skeleton(base)
    trusted_names = [trusted.split(".", 1)[0] for trusted in trusted_domains]
    candidates = sorted(set(trusted_names + protected_brands))
    for candidate in candidates:
        if not candidate or base == candidate:
            continue
        candidate_skeleton = _skeleton(candidate)
        similarity = SequenceMatcher(None, base_skeleton, candidate_skeleton).ratio()
        if similarity >= 0.82 or candidate_skeleton in base_skeleton or base_skeleton in candidate_skeleton:
            return candidate
    return ""


def evaluate_trust(
    sender: str,
    trusted_domains: list[str],
    trusted_senders: list[str],
) -> list[TrustSignalResult]:
    sender_domain = domain_from_sender(sender)
    sender_address = _address_from_sender(sender)
    signals: list[TrustSignalResult] = []
    if sender_address and sender_address in trusted_senders:
        signals.append(
            TrustSignalResult(
                "Known sender",
                "The exact sender address is in the configured allow-context list.",
                -14,
            )
        )
    if sender_domain and any(
        sender_domain == domain or sender_domain.endswith(f".{domain}") for domain in trusted_domains
    ):
        signals.append(
            TrustSignalResult(
                "Trusted organization domain",
                "The sender domain matches the configured organization context.",
                -10,
            )
        )
    return signals
