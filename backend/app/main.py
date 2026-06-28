import json
import logging
import secrets
import time
from collections import defaultdict, deque
from datetime import UTC, datetime
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .config import settings
from .detector import analyze
from .mailbox import read_mailbox_history
from .parser import parse_eml
from .schemas import (
    AnalysisResponse,
    AuditEvent,
    ComplianceExport,
    CurrentUser,
    DashboardMetrics,
    DataDeletionRequest,
    DataDeletionResponse,
    EmailInput,
    FeedbackInput,
    MailboxHistoryRecord,
    OrgSettings,
    ScanHistoryRecord,
    SecurityPosture,
    SubscriptionPlan,
    ThreatIntelPreview,
    UsageSummary,
)
from .storage import (
    RequestContext,
    can_create_scan,
    compliance_export,
    dashboard_metrics,
    delete_org_data,
    get_org_settings,
    get_subscription,
    init_storage,
    list_audit_events,
    list_scan_history,
    normalize_context,
    record_feedback,
    record_scan,
    save_org_settings,
    save_subscription,
    security_posture,
    usage_summary,
)
from .threat_intel import preview_threat_intel

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)
_RATE_LIMIT_BUCKETS: dict[str, deque[float]] = defaultdict(deque)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'; base-uri 'none'"
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/api/") and request.url.path != "/api/health":
            forwarded_for = request.headers.get("x-forwarded-for", "")
            client = forwarded_for.split(",", 1)[0].strip() if forwarded_for else ""
            client = client or (request.client.host if request.client else "unknown")
            now = time.monotonic()
            bucket = _RATE_LIMIT_BUCKETS[client]
            window_start = now - settings.rate_limit_window_seconds
            while bucket and bucket[0] < window_start:
                bucket.popleft()
            if len(bucket) >= settings.rate_limit_requests:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests. Please wait and retry."},
                    headers={"Retry-After": str(settings.rate_limit_window_seconds)},
                )
            bucket.append(now)
        return await call_next(request)


def require_api_key(x_api_key: str = Header(default="")) -> None:
    if settings.api_key and not secrets.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(status_code=401, detail="A valid API key is required.")


def request_context(
    x_org_id: str = Header(default="demo-org"),
    x_user_id: str = Header(default="anonymous"),
) -> RequestContext:
    return normalize_context(x_org_id, x_user_id)


app = FastAPI(
    title=settings.app_name,
    description="Explainable hybrid phishing-email risk analysis. Submitted content is processed in memory.",
    version="1.0.0",
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.hosts)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "X-API-Key", "X-Org-ID", "X-User-ID"],
)


@app.on_event("startup")
def startup() -> None:
    init_storage()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}


@app.get("/api/me", response_model=CurrentUser, dependencies=[Depends(require_api_key)])
def me(context: RequestContext = Depends(request_context)) -> CurrentUser:
    return CurrentUser(
        org_id=context.org_id,
        user_id=context.user_id,
        role=context.role,
        auth_mode=settings.auth_mode,
        permissions=[
            "scan:write",
            "scan:read",
            "settings:read",
            "settings:write",
            "feedback:write",
            "audit:read",
            "compliance:export",
        ],
    )


@app.get("/api/org/settings", response_model=OrgSettings, dependencies=[Depends(require_api_key)])
def org_settings(context: RequestContext = Depends(request_context)) -> OrgSettings:
    return get_org_settings(context)


@app.put("/api/org/settings", response_model=OrgSettings, dependencies=[Depends(require_api_key)])
def update_org_settings(
    payload: OrgSettings,
    context: RequestContext = Depends(request_context),
) -> OrgSettings:
    return save_org_settings(context, payload)


@app.get(
    "/api/billing/subscription", response_model=SubscriptionPlan, dependencies=[Depends(require_api_key)]
)
def subscription(context: RequestContext = Depends(request_context)) -> SubscriptionPlan:
    return get_subscription(context)


@app.put(
    "/api/billing/subscription", response_model=SubscriptionPlan, dependencies=[Depends(require_api_key)]
)
def update_subscription(
    payload: SubscriptionPlan,
    context: RequestContext = Depends(request_context),
) -> SubscriptionPlan:
    return save_subscription(context, payload)


@app.get("/api/billing/usage", response_model=UsageSummary, dependencies=[Depends(require_api_key)])
def usage(context: RequestContext = Depends(request_context)) -> UsageSummary:
    return usage_summary(context)


@app.post("/api/analyze", response_model=AnalysisResponse, dependencies=[Depends(require_api_key)])
def analyze_email(
    payload: EmailInput,
    context: RequestContext = Depends(request_context),
) -> AnalysisResponse:
    if not can_create_scan(context):
        raise HTTPException(status_code=402, detail="Monthly scan limit reached for this workspace.")
    saved_settings = get_org_settings(context)
    trusted_domains = payload.trusted_domains or saved_settings.trusted_domains
    trusted_senders = payload.trusted_senders or saved_settings.trusted_senders
    result = analyze(
        payload.sender,
        payload.subject,
        payload.body,
        payload.headers,
        trusted_domains=tuple(trusted_domains),
        trusted_senders=tuple(trusted_senders),
        sensitivity=payload.sensitivity or saved_settings.sensitivity,
    )
    record_scan(context, "pasted", payload.sender, payload.subject, payload.body, result)
    return result


@app.post("/api/analyze-eml", response_model=AnalysisResponse, dependencies=[Depends(require_api_key)])
async def analyze_eml(
    file: UploadFile = File(...),
    sender_override: str = Form(default=""),
    context: RequestContext = Depends(request_context),
) -> AnalysisResponse:
    if not can_create_scan(context):
        raise HTTPException(status_code=402, detail="Monthly scan limit reached for this workspace.")
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=415, detail="Only .eml files are accepted.")
    content = await file.read(settings.max_email_bytes + 1)
    if len(content) > settings.max_email_bytes:
        raise HTTPException(status_code=413, detail="The email exceeds the configured size limit.")
    try:
        parsed = parse_eml(content)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.warning("Unable to parse uploaded EML: %s", type(exc).__name__)
        raise HTTPException(status_code=422, detail="The EML file could not be parsed safely.") from exc
    result = analyze(
        sender_override or parsed.sender, parsed.subject, parsed.body, parsed.headers, parsed.attachments
    )
    record_scan(context, "eml_upload", sender_override or parsed.sender, parsed.subject, parsed.body, result)
    return result


@app.post("/api/feedback", dependencies=[Depends(require_api_key)])
def submit_feedback(
    payload: FeedbackInput,
    context: RequestContext = Depends(request_context),
) -> dict[str, str]:
    path = Path(settings.feedback_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "analysis_id": payload.analysis_id,
        "label": payload.label,
        "note": payload.note,
        "created_at": datetime.now(UTC).isoformat(),
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    record_feedback(context, payload.analysis_id, payload.label, payload.note)
    return {"status": "recorded"}


@app.get(
    "/api/scans/history",
    response_model=list[ScanHistoryRecord],
    dependencies=[Depends(require_api_key)],
)
def scan_history(
    limit: int = Query(default=50, ge=1, le=200),
    context: RequestContext = Depends(request_context),
) -> list[ScanHistoryRecord]:
    return list_scan_history(context, limit)


@app.get(
    "/api/dashboard/metrics",
    response_model=DashboardMetrics,
    dependencies=[Depends(require_api_key)],
)
def metrics(context: RequestContext = Depends(request_context)) -> DashboardMetrics:
    return dashboard_metrics(context)


@app.get(
    "/api/audit/events",
    response_model=list[AuditEvent],
    dependencies=[Depends(require_api_key)],
)
def audit_events(
    limit: int = Query(default=50, ge=1, le=200),
    context: RequestContext = Depends(request_context),
) -> list[AuditEvent]:
    return list_audit_events(context, limit)


@app.get(
    "/api/compliance/export",
    response_model=ComplianceExport,
    dependencies=[Depends(require_api_key)],
)
def export_compliance_data(context: RequestContext = Depends(request_context)) -> ComplianceExport:
    return compliance_export(context)


@app.delete(
    "/api/compliance/data",
    response_model=DataDeletionResponse,
    dependencies=[Depends(require_api_key)],
)
def delete_compliance_data(
    payload: DataDeletionRequest,
    context: RequestContext = Depends(request_context),
) -> DataDeletionResponse:
    if payload.confirm_org_id != context.org_id:
        raise HTTPException(status_code=400, detail="Confirmation org ID does not match this workspace.")
    return delete_org_data(
        context,
        include_feedback=payload.include_feedback,
        include_audit_logs=payload.include_audit_logs,
    )


@app.get(
    "/api/security/posture",
    response_model=SecurityPosture,
    dependencies=[Depends(require_api_key)],
)
def posture(context: RequestContext = Depends(request_context)) -> SecurityPosture:
    return security_posture(context)


@app.post(
    "/api/threat-intel/preview",
    response_model=ThreatIntelPreview,
    dependencies=[Depends(require_api_key)],
)
def threat_intel_preview(payload: EmailInput) -> ThreatIntelPreview:
    return preview_threat_intel(f"{payload.subject}\n{payload.body}")


@app.get(
    "/api/mailbox/history",
    response_model=list[MailboxHistoryRecord],
    dependencies=[Depends(require_api_key)],
)
def mailbox_history(limit: int = Query(default=50, ge=1, le=200)) -> list[MailboxHistoryRecord]:
    return read_mailbox_history(limit)
