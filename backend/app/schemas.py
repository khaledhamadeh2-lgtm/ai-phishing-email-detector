from pydantic import BaseModel, Field


class EmailInput(BaseModel):
    sender: str = Field(default="", max_length=500)
    subject: str = Field(default="", max_length=1_000)
    body: str = Field(min_length=1, max_length=250_000)
    headers: dict[str, str] = Field(default_factory=dict)
    trusted_domains: list[str] = Field(default_factory=list, max_length=50)
    trusted_senders: list[str] = Field(default_factory=list, max_length=100)
    sensitivity: str = Field(default="balanced", pattern="^(balanced|recall|precision)$")


class RiskFactor(BaseModel):
    id: str
    title: str
    detail: str
    severity: str
    weight: int


class Highlight(BaseModel):
    text: str
    kind: str
    explanation: str


class AttachmentFinding(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    risk_level: str
    reasons: list[str]
    score: int


class TrustSignal(BaseModel):
    title: str
    detail: str
    adjustment: int


class FeedbackInput(BaseModel):
    analysis_id: str = Field(min_length=12, max_length=64)
    label: str = Field(pattern="^(safe|suspicious|phishing|false_positive|false_negative)$")
    note: str = Field(default="", max_length=1_000)


class MailboxHistoryRecord(BaseModel):
    uid: str
    fingerprint: str
    analysis_id: str
    scanned_at: str
    sender: str
    subject: str
    probability: float
    verdict: str
    risk_factors: list[str]
    attachment_count: int


class AnalysisResponse(BaseModel):
    analysis_id: str
    probability: float
    verdict: str
    rule_score: float
    model_score: float
    risk_factors: list[RiskFactor]
    trust_signals: list[TrustSignal]
    attachments: list[AttachmentFinding]
    highlights: list[Highlight]
    recommendations: list[str]
    model_version: str
    analyzed_headers: bool
    sensitivity: str
    suspicious_threshold: float
    likely_phishing_threshold: float
