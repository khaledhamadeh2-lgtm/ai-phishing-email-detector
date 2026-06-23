from pydantic import BaseModel, Field


class EmailInput(BaseModel):
    sender: str = Field(default="", max_length=500)
    subject: str = Field(default="", max_length=1_000)
    body: str = Field(min_length=1, max_length=250_000)
    headers: dict[str, str] = Field(default_factory=dict)


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


class AnalysisResponse(BaseModel):
    probability: float
    verdict: str
    rule_score: float
    model_score: float
    risk_factors: list[RiskFactor]
    highlights: list[Highlight]
    recommendations: list[str]
    model_version: str
    analyzed_headers: bool
