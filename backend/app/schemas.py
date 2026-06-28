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


class TenantContext(BaseModel):
    org_id: str
    user_id: str
    role: str = "analyst"


class CurrentUser(BaseModel):
    org_id: str
    user_id: str
    role: str
    auth_mode: str
    permissions: list[str]


class OrgSettings(BaseModel):
    org_id: str
    trusted_domains: list[str] = Field(default_factory=list, max_length=50)
    trusted_senders: list[str] = Field(default_factory=list, max_length=100)
    sensitivity: str = Field(default="balanced", pattern="^(balanced|recall|precision)$")
    scan_retention_days: int = Field(default=30, ge=1, le=365)
    store_email_bodies: bool = False
    mailbox_alert_threshold: float = Field(default=70.0, ge=0.0, le=100.0)


class DashboardMetrics(BaseModel):
    org_id: str
    total_scans: int
    safe_count: int
    suspicious_count: int
    likely_phishing_count: int
    attachment_scan_count: int
    feedback_count: int
    false_positive_count: int
    top_risk_factors: list[dict[str, int | str]]


class ThreatIntelFinding(BaseModel):
    provider: str
    status: str
    detail: str


class ThreatIntelPreview(BaseModel):
    enabled: bool
    domains: list[str]
    findings: list[ThreatIntelFinding]
    privacy_note: str


class ScanHistoryRecord(BaseModel):
    analysis_id: str
    org_id: str
    user_id: str
    source: str
    scanned_at: str
    sender: str
    subject: str
    probability: float
    verdict: str
    risk_factors: list[str]
    attachment_count: int
    body_sha256: str


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
