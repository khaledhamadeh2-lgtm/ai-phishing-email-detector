from urllib.parse import urlsplit

from .config import settings
from .rules import URL_PATTERN
from .schemas import ThreatIntelFinding, ThreatIntelPreview


def extract_domains(text: str, limit: int = 20) -> list[str]:
    domains: list[str] = []
    for raw_url in URL_PATTERN.findall(text)[:limit]:
        host = (urlsplit(raw_url).hostname or "").lower().rstrip(".")
        if host and host not in domains:
            domains.append(host)
    return domains


def preview_threat_intel(text: str) -> ThreatIntelPreview:
    """Privacy-safe reputation preview.

    This intentionally does not call external services yet. Some reputation providers receive submitted
    URL/domain metadata, so production integrations should be opt-in, documented, and key-backed.
    """
    domains = extract_domains(text)
    findings: list[ThreatIntelFinding] = []
    if not domains:
        findings.append(
            ThreatIntelFinding(
                provider="local",
                status="no_domains",
                detail="No URL domains were found to enrich.",
            )
        )
    for provider in settings.threat_intel_provider_list:
        findings.append(
            ThreatIntelFinding(
                provider=provider,
                status="not_configured" if not settings.threat_intel_enabled else "ready_for_provider_key",
                detail=(
                    "Provider integration is scaffolded but disabled to avoid leaking URL metadata "
                    "without consent."
                ),
            )
        )
    return ThreatIntelPreview(
        enabled=settings.threat_intel_enabled,
        domains=domains,
        findings=findings,
        privacy_note=(
            "No external reputation lookups were performed. Future providers should use hashes or documented "
            "domain-only lookups where possible."
        ),
    )
