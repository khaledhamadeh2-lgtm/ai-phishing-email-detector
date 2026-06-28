import hashlib
from functools import lru_cache
from pathlib import Path

import joblib

from .attachments import AttachmentRisk
from .config import settings
from .org_context import evaluate_trust
from .rules import evaluate
from .schemas import AnalysisResponse, AttachmentFinding, Highlight, RiskFactor, TrustSignal

MODEL_VERSION = "phishguard-v3"


@lru_cache(maxsize=1)
def load_model():
    path = Path(settings.model_path)
    if not path.exists():
        return None
    return joblib.load(path)


def _analysis_id(sender: str, subject: str, body: str) -> str:
    digest = hashlib.sha256(f"{sender}\n{subject}\n{body}".encode("utf-8", errors="replace")).hexdigest()
    return digest[:24]


def analyze(
    sender: str,
    subject: str,
    body: str,
    headers: dict[str, str] | None = None,
    attachments: tuple[AttachmentRisk, ...] = (),
    trusted_domains: tuple[str, ...] = (),
    trusted_senders: tuple[str, ...] = (),
    sensitivity: str = "balanced",
) -> AnalysisResponse:
    findings = evaluate(sender, subject, body, headers)
    rule_score = min(100.0, float(sum(f.weight for f in findings)))
    attachment_score = min(60.0, float(sum(item.score for item in attachments)))
    context_domains = sorted(set(settings.trusted_domain_list + [d.lower() for d in trusted_domains]))
    context_senders = sorted(set(settings.trusted_sender_list + [s.lower() for s in trusted_senders]))
    trust_signals = evaluate_trust(sender, context_domains, context_senders)
    trust_adjustment = max(-24.0, float(sum(signal.adjustment for signal in trust_signals)))
    model = load_model()
    model_score = 50.0
    if model is not None:
        model_text = f"From: {sender}\nSubject: {subject}\n\n{body}"
        model_score = float(model.predict_proba([model_text])[0][1] * 100)

    # Rules receive extra weight so explanations and dangerous URL patterns remain decisive.
    blended_score = 0.52 * model_score + 0.36 * rule_score + 0.12 * attachment_score + trust_adjustment
    if rule_score >= 70:
        blended_score = max(blended_score, 70 + min(15, (rule_score - 70) * 0.35))
    if attachment_score >= 40:
        blended_score = max(blended_score, 62 + min(18, (attachment_score - 40) * 0.4))
    if rule_score == 0 and attachment_score < 18 and model_score < 85:
        blended_score = min(blended_score, 34.0)

    probability = round(min(99.0, max(1.0, blended_score)), 1)
    sensitivity = sensitivity if sensitivity in {"balanced", "recall", "precision"} else "balanced"
    suspicious_threshold = settings.suspicious_threshold
    likely_threshold = settings.likely_phishing_threshold
    if sensitivity == "recall":
        suspicious_threshold = max(20.0, suspicious_threshold - 10)
        likely_threshold = max(55.0, likely_threshold - 8)
    elif sensitivity == "precision":
        suspicious_threshold = min(55.0, suspicious_threshold + 10)
        likely_threshold = min(88.0, likely_threshold + 8)
    verdict = (
        "Likely Phishing"
        if probability >= likely_threshold
        else "Suspicious"
        if probability >= suspicious_threshold
        else "Safe"
    )
    recommendations = (
        [
            "Do not click links, open attachments, reply, or provide credentials.",
            "Verify the request through a trusted channel you find independently.",
            "Report the message to your security team or email provider.",
        ]
        if verdict != "Safe"
        else [
            "Remain cautious with unexpected links and attachments.",
            "Verify sensitive requests through a separate trusted channel.",
        ]
    )
    return AnalysisResponse(
        analysis_id=_analysis_id(sender, subject, body),
        probability=probability,
        verdict=verdict,
        rule_score=round(rule_score, 1),
        model_score=round(model_score, 1),
        risk_factors=[
            RiskFactor(id=f.id, title=f.title, detail=f.detail, severity=f.severity, weight=f.weight)
            for f in findings
        ],
        trust_signals=[
            TrustSignal(title=signal.title, detail=signal.detail, adjustment=signal.adjustment)
            for signal in trust_signals
        ],
        attachments=[
            AttachmentFinding(
                filename=item.filename,
                content_type=item.content_type,
                size_bytes=item.size_bytes,
                sha256=item.sha256,
                risk_level=item.risk_level,
                reasons=list(item.reasons),
                score=item.score,
            )
            for item in attachments
        ],
        highlights=[
            Highlight(text=f.evidence, kind=f.kind, explanation=f.detail) for f in findings if f.evidence
        ],
        recommendations=recommendations,
        model_version=MODEL_VERSION,
        analyzed_headers=bool(headers),
        sensitivity=sensitivity,
        suspicious_threshold=round(suspicious_threshold, 1),
        likely_phishing_threshold=round(likely_threshold, 1),
    )
