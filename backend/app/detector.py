from functools import lru_cache
from pathlib import Path

import joblib

from .config import settings
from .rules import evaluate
from .schemas import AnalysisResponse, Highlight, RiskFactor

MODEL_VERSION = "phishguard-v1"


@lru_cache(maxsize=1)
def load_model():
    path = Path(settings.model_path)
    if not path.exists():
        return None
    return joblib.load(path)


def analyze(sender: str, subject: str, body: str) -> AnalysisResponse:
    findings = evaluate(sender, subject, body)
    rule_score = min(100.0, float(sum(f.weight for f in findings)))
    model = load_model()
    model_score = 50.0
    if model is not None:
        model_text = f"From: {sender}\nSubject: {subject}\n\n{body}"
        model_score = float(model.predict_proba([model_text])[0][1] * 100)

    # Rules receive extra weight so explanations and dangerous URL patterns remain decisive.
    probability = round(min(99.0, max(1.0, 0.58 * model_score + 0.42 * rule_score)), 1)
    verdict = "Likely Phishing" if probability >= 70 else "Suspicious" if probability >= 35 else "Safe"
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
        probability=probability,
        verdict=verdict,
        rule_score=round(rule_score, 1),
        model_score=round(model_score, 1),
        risk_factors=[
            RiskFactor(id=f.id, title=f.title, detail=f.detail, severity=f.severity, weight=f.weight)
            for f in findings
        ],
        highlights=[
            Highlight(text=f.evidence, kind=f.kind, explanation=f.detail) for f in findings if f.evidence
        ],
        recommendations=recommendations,
        model_version=MODEL_VERSION,
    )
