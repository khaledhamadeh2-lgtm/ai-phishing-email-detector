import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .config import settings
from .schemas import (
    AnalysisResponse,
    AuditEvent,
    ComplianceExport,
    DashboardMetrics,
    DataDeletionResponse,
    OrgSettings,
    ScanHistoryRecord,
    SecurityPosture,
    SubscriptionPlan,
    UsageSummary,
)


@dataclass(frozen=True)
class RequestContext:
    org_id: str = "demo-org"
    user_id: str = "anonymous"
    role: str = "analyst"


def normalize_context(org_id: str = "", user_id: str = "") -> RequestContext:
    return RequestContext(
        org_id=(org_id or "demo-org").strip()[:120],
        user_id=(user_id or "anonymous").strip()[:120],
        role="analyst",
    )


@contextmanager
def _connect():
    path = Path(settings.database_path)
    if os.name == "nt" and str(path).replace("\\", "/").startswith("/tmp/"):
        path = Path(tempfile.gettempdir()) / path.name
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_storage() -> None:
    if not settings.database_enabled:
        return
    with _connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                source TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                sender TEXT NOT NULL,
                subject TEXT NOT NULL,
                probability REAL NOT NULL,
                verdict TEXT NOT NULL,
                risk_factors_json TEXT NOT NULL,
                attachment_count INTEGER NOT NULL,
                body_sha256 TEXT NOT NULL,
                body_preview TEXT
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_events_org_time ON scan_events(org_id, scanned_at DESC)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS feedback_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                label TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_feedback_events_analysis ON feedback_events(analysis_id)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS org_settings (
                org_id TEXT PRIMARY KEY,
                trusted_domains_json TEXT NOT NULL,
                trusted_senders_json TEXT NOT NULL,
                sensitivity TEXT NOT NULL,
                scan_retention_days INTEGER NOT NULL,
                store_email_bodies INTEGER NOT NULL,
                mailbox_alert_threshold REAL NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS org_subscriptions (
                org_id TEXT PRIMARY KEY,
                plan TEXT NOT NULL,
                monthly_scan_limit INTEGER NOT NULL,
                mailbox_accounts_limit INTEGER NOT NULL,
                retention_days_limit INTEGER NOT NULL,
                threat_intel_enabled INTEGER NOT NULL,
                audit_log_enabled INTEGER NOT NULL,
                billing_status TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_events_org_time ON audit_events(org_id, created_at DESC)"
        )


def enforce_retention() -> None:
    if not settings.database_enabled:
        return
    cutoff = datetime.now(UTC) - timedelta(days=settings.scan_retention_days)
    with _connect() as connection:
        connection.execute("DELETE FROM scan_events WHERE scanned_at < ?", (cutoff.isoformat(),))


def record_scan(
    context: RequestContext,
    source: str,
    sender: str,
    subject: str,
    body: str,
    result: AnalysisResponse,
) -> None:
    if not settings.database_enabled:
        return
    init_storage()
    body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
    risk_titles = [factor.title for factor in result.risk_factors[:5]]
    body_preview = body[:500] if settings.store_email_bodies else None
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO scan_events (
                analysis_id, org_id, user_id, source, scanned_at, sender, subject, probability,
                verdict, risk_factors_json, attachment_count, body_sha256, body_preview
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.analysis_id,
                context.org_id,
                context.user_id,
                source,
                datetime.now(UTC).isoformat(),
                sender[:500],
                subject[:1_000],
                result.probability,
                result.verdict,
                json.dumps(risk_titles, ensure_ascii=False),
                len(result.attachments),
                body_hash,
                body_preview,
            ),
        )
    enforce_retention()
    record_audit_event(
        context,
        "scan.created",
        result.analysis_id,
        {"source": source, "verdict": result.verdict, "probability": round(result.probability, 2)},
    )


def list_scan_history(context: RequestContext, limit: int = 50) -> list[ScanHistoryRecord]:
    if not settings.database_enabled:
        return []
    init_storage()
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT analysis_id, org_id, user_id, source, scanned_at, sender, subject, probability,
                   verdict, risk_factors_json, attachment_count, body_sha256
            FROM scan_events
            WHERE org_id = ?
            ORDER BY scanned_at DESC, id DESC
            LIMIT ?
            """,
            (context.org_id, limit),
        ).fetchall()
    return [
        ScanHistoryRecord(
            analysis_id=row["analysis_id"],
            org_id=row["org_id"],
            user_id=row["user_id"],
            source=row["source"],
            scanned_at=row["scanned_at"],
            sender=row["sender"],
            subject=row["subject"],
            probability=row["probability"],
            verdict=row["verdict"],
            risk_factors=json.loads(row["risk_factors_json"]),
            attachment_count=row["attachment_count"],
            body_sha256=row["body_sha256"],
        )
        for row in rows
    ]


def record_feedback(context: RequestContext, analysis_id: str, label: str, note: str) -> None:
    if not settings.database_enabled:
        return
    init_storage()
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO feedback_events (analysis_id, org_id, user_id, label, note, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (analysis_id, context.org_id, context.user_id, label, note, datetime.now(UTC).isoformat()),
        )
    record_audit_event(context, "feedback.created", analysis_id, {"label": label})


def get_org_settings(context: RequestContext) -> OrgSettings:
    if not settings.database_enabled:
        return _default_org_settings(context.org_id)
    init_storage()
    with _connect() as connection:
        row = connection.execute(
            "SELECT * FROM org_settings WHERE org_id = ?",
            (context.org_id,),
        ).fetchone()
    if row is None:
        return _default_org_settings(context.org_id)
    return OrgSettings(
        org_id=row["org_id"],
        trusted_domains=json.loads(row["trusted_domains_json"]),
        trusted_senders=json.loads(row["trusted_senders_json"]),
        sensitivity=row["sensitivity"],
        scan_retention_days=row["scan_retention_days"],
        store_email_bodies=bool(row["store_email_bodies"]),
        mailbox_alert_threshold=row["mailbox_alert_threshold"],
    )


def save_org_settings(context: RequestContext, payload: OrgSettings) -> OrgSettings:
    if not settings.database_enabled:
        return payload
    init_storage()
    normalized = OrgSettings(
        org_id=context.org_id,
        trusted_domains=sorted({item.strip().lower() for item in payload.trusted_domains if item.strip()}),
        trusted_senders=sorted({item.strip().lower() for item in payload.trusted_senders if item.strip()}),
        sensitivity=payload.sensitivity,
        scan_retention_days=payload.scan_retention_days,
        store_email_bodies=payload.store_email_bodies,
        mailbox_alert_threshold=payload.mailbox_alert_threshold,
    )
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO org_settings (
                org_id, trusted_domains_json, trusted_senders_json, sensitivity,
                scan_retention_days, store_email_bodies, mailbox_alert_threshold, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(org_id) DO UPDATE SET
                trusted_domains_json = excluded.trusted_domains_json,
                trusted_senders_json = excluded.trusted_senders_json,
                sensitivity = excluded.sensitivity,
                scan_retention_days = excluded.scan_retention_days,
                store_email_bodies = excluded.store_email_bodies,
                mailbox_alert_threshold = excluded.mailbox_alert_threshold,
                updated_at = excluded.updated_at
            """,
            (
                normalized.org_id,
                json.dumps(normalized.trusted_domains, ensure_ascii=False),
                json.dumps(normalized.trusted_senders, ensure_ascii=False),
                normalized.sensitivity,
                normalized.scan_retention_days,
                int(normalized.store_email_bodies),
                normalized.mailbox_alert_threshold,
                datetime.now(UTC).isoformat(),
            ),
        )
    record_audit_event(
        context,
        "settings.updated",
        context.org_id,
        {"sensitivity": normalized.sensitivity, "retention_days": normalized.scan_retention_days},
    )
    return normalized


def get_subscription(context: RequestContext) -> SubscriptionPlan:
    if not settings.database_enabled:
        return _default_subscription(context.org_id)
    init_storage()
    with _connect() as connection:
        row = connection.execute(
            "SELECT * FROM org_subscriptions WHERE org_id = ?",
            (context.org_id,),
        ).fetchone()
    if row is None:
        return _default_subscription(context.org_id)
    return SubscriptionPlan(
        org_id=row["org_id"],
        plan=row["plan"],
        monthly_scan_limit=row["monthly_scan_limit"],
        mailbox_accounts_limit=row["mailbox_accounts_limit"],
        retention_days_limit=row["retention_days_limit"],
        threat_intel_enabled=bool(row["threat_intel_enabled"]),
        audit_log_enabled=bool(row["audit_log_enabled"]),
        billing_status=row["billing_status"],
    )


def save_subscription(context: RequestContext, payload: SubscriptionPlan) -> SubscriptionPlan:
    if not settings.database_enabled:
        return payload
    init_storage()
    normalized = SubscriptionPlan(
        org_id=context.org_id,
        plan=payload.plan,
        monthly_scan_limit=payload.monthly_scan_limit,
        mailbox_accounts_limit=payload.mailbox_accounts_limit,
        retention_days_limit=payload.retention_days_limit,
        threat_intel_enabled=payload.threat_intel_enabled,
        audit_log_enabled=payload.audit_log_enabled,
        billing_status=payload.billing_status,
    )
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO org_subscriptions (
                org_id, plan, monthly_scan_limit, mailbox_accounts_limit, retention_days_limit,
                threat_intel_enabled, audit_log_enabled, billing_status, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(org_id) DO UPDATE SET
                plan = excluded.plan,
                monthly_scan_limit = excluded.monthly_scan_limit,
                mailbox_accounts_limit = excluded.mailbox_accounts_limit,
                retention_days_limit = excluded.retention_days_limit,
                threat_intel_enabled = excluded.threat_intel_enabled,
                audit_log_enabled = excluded.audit_log_enabled,
                billing_status = excluded.billing_status,
                updated_at = excluded.updated_at
            """,
            (
                normalized.org_id,
                normalized.plan,
                normalized.monthly_scan_limit,
                normalized.mailbox_accounts_limit,
                normalized.retention_days_limit,
                int(normalized.threat_intel_enabled),
                int(normalized.audit_log_enabled),
                normalized.billing_status,
                datetime.now(UTC).isoformat(),
            ),
        )
    record_audit_event(
        context,
        "subscription.updated",
        context.org_id,
        {"plan": normalized.plan, "monthly_scan_limit": normalized.monthly_scan_limit},
    )
    return normalized


def usage_summary(context: RequestContext) -> UsageSummary:
    subscription = get_subscription(context)
    period_start, period_end = _monthly_period()
    scans_used = _count_scans(context, period_start, period_end)
    remaining = max(subscription.monthly_scan_limit - scans_used, 0)
    return UsageSummary(
        org_id=context.org_id,
        plan=subscription.plan,
        period_start=period_start.isoformat(),
        period_end=period_end.isoformat(),
        scans_used=scans_used,
        monthly_scan_limit=subscription.monthly_scan_limit,
        scans_remaining=remaining,
        usage_percent=round((scans_used / subscription.monthly_scan_limit) * 100, 2),
        limit_enforced=settings.enforce_plan_limits,
    )


def can_create_scan(context: RequestContext) -> bool:
    if not settings.enforce_plan_limits:
        return True
    summary = usage_summary(context)
    return summary.scans_remaining > 0


def record_audit_event(
    context: RequestContext,
    action: str,
    target: str,
    metadata: dict[str, str | int | float | bool] | None = None,
) -> None:
    if not settings.database_enabled:
        return
    init_storage()
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO audit_events (org_id, user_id, action, target, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                context.org_id,
                context.user_id,
                action,
                target,
                json.dumps(metadata or {}, ensure_ascii=False),
                datetime.now(UTC).isoformat(),
            ),
        )


def list_audit_events(context: RequestContext, limit: int = 100) -> list[AuditEvent]:
    if not settings.database_enabled:
        return []
    init_storage()
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT id, org_id, user_id, action, target, metadata_json, created_at
            FROM audit_events
            WHERE org_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (context.org_id, limit),
        ).fetchall()
    return [
        AuditEvent(
            event_id=row["id"],
            org_id=row["org_id"],
            user_id=row["user_id"],
            action=row["action"],
            target=row["target"],
            metadata=json.loads(row["metadata_json"]),
            created_at=row["created_at"],
        )
        for row in rows
    ]


def compliance_export(context: RequestContext) -> ComplianceExport:
    if not settings.database_enabled:
        return ComplianceExport(
            org_id=context.org_id,
            generated_at=datetime.now(UTC).isoformat(),
            scans=[],
            feedback_count=0,
            audit_events=[],
            privacy_note="Database storage is disabled, so there is no persisted tenant data to export.",
        )
    init_storage()
    with _connect() as connection:
        feedback_count = connection.execute(
            "SELECT COUNT(*) FROM feedback_events WHERE org_id = ?",
            (context.org_id,),
        ).fetchone()[0]
    record_audit_event(context, "compliance.exported", context.org_id, {"format": "json"})
    return ComplianceExport(
        org_id=context.org_id,
        generated_at=datetime.now(UTC).isoformat(),
        scans=list_scan_history(context, limit=500),
        feedback_count=feedback_count,
        audit_events=list_audit_events(context, limit=200),
        privacy_note=(
            "Export contains redacted scan metadata and audit events. "
            "Full email bodies are excluded by default."
        ),
    )


def delete_org_data(
    context: RequestContext,
    include_feedback: bool = True,
    include_audit_logs: bool = False,
) -> DataDeletionResponse:
    if not settings.database_enabled:
        return DataDeletionResponse(
            org_id=context.org_id,
            deleted_scans=0,
            deleted_feedback=0,
            deleted_audit_events=0,
            status="database-disabled",
        )
    init_storage()
    with _connect() as connection:
        deleted_scans = connection.execute(
            "DELETE FROM scan_events WHERE org_id = ?",
            (context.org_id,),
        ).rowcount
        deleted_feedback = 0
        deleted_audit = 0
        if include_feedback:
            deleted_feedback = connection.execute(
                "DELETE FROM feedback_events WHERE org_id = ?",
                (context.org_id,),
            ).rowcount
        if include_audit_logs:
            deleted_audit = connection.execute(
                "DELETE FROM audit_events WHERE org_id = ?",
                (context.org_id,),
            ).rowcount
    if not include_audit_logs:
        record_audit_event(
            context,
            "compliance.deleted",
            context.org_id,
            {"deleted_scans": deleted_scans, "deleted_feedback": deleted_feedback},
        )
    return DataDeletionResponse(
        org_id=context.org_id,
        deleted_scans=deleted_scans,
        deleted_feedback=deleted_feedback,
        deleted_audit_events=deleted_audit,
        status="deleted",
    )


def security_posture(context: RequestContext) -> SecurityPosture:
    controls = [
        "Submitted links are parsed but never visited.",
        "Attachments are statically triaged and never executed.",
        "Scan history stores redacted metadata and a body hash by default.",
        "Tenant headers isolate demo workspace data.",
        "Rate limiting and security headers are enabled.",
    ]
    next_steps = [
        "Replace demo headers with a production identity provider.",
        "Terminate TLS at the edge and restrict CORS to deployed domains.",
        "Move SQLite demo storage to managed PostgreSQL before public launch.",
        "Connect paid threat-intel providers only after privacy notices are approved.",
    ]
    if settings.api_key:
        controls.append("API key protection is enabled.")
    else:
        next_steps.insert(0, "Set PHISHGUARD_API_KEY before exposing the API outside localhost.")
    return SecurityPosture(
        org_id=context.org_id,
        api_key_required=bool(settings.api_key),
        auth_mode=settings.auth_mode,
        database_enabled=settings.database_enabled,
        store_email_bodies=get_org_settings(context).store_email_bodies,
        threat_intel_enabled=settings.threat_intel_enabled,
        rate_limit=f"{settings.rate_limit_requests} requests / {settings.rate_limit_window_seconds}s",
        controls=controls,
        recommended_next_steps=next_steps,
    )


def dashboard_metrics(context: RequestContext) -> DashboardMetrics:
    if not settings.database_enabled:
        return DashboardMetrics(
            org_id=context.org_id,
            total_scans=0,
            safe_count=0,
            suspicious_count=0,
            likely_phishing_count=0,
            attachment_scan_count=0,
            feedback_count=0,
            false_positive_count=0,
            top_risk_factors=[],
        )
    init_storage()
    with _connect() as connection:
        rows = connection.execute(
            "SELECT verdict, risk_factors_json, attachment_count FROM scan_events WHERE org_id = ?",
            (context.org_id,),
        ).fetchall()
        feedback_rows = connection.execute(
            "SELECT label FROM feedback_events WHERE org_id = ?",
            (context.org_id,),
        ).fetchall()
    verdicts = [row["verdict"] for row in rows]
    risk_counts: dict[str, int] = {}
    for row in rows:
        for title in json.loads(row["risk_factors_json"]):
            risk_counts[title] = risk_counts.get(title, 0) + 1
    top_risks = [
        {"title": title, "count": count}
        for title, count in sorted(risk_counts.items(), key=lambda item: item[1], reverse=True)[:5]
    ]
    return DashboardMetrics(
        org_id=context.org_id,
        total_scans=len(rows),
        safe_count=verdicts.count("Safe"),
        suspicious_count=verdicts.count("Suspicious"),
        likely_phishing_count=verdicts.count("Likely Phishing"),
        attachment_scan_count=sum(1 for row in rows if row["attachment_count"] > 0),
        feedback_count=len(feedback_rows),
        false_positive_count=sum(1 for row in feedback_rows if row["label"] == "false_positive"),
        top_risk_factors=top_risks,
    )


def _default_org_settings(org_id: str) -> OrgSettings:
    return OrgSettings(
        org_id=org_id,
        trusted_domains=settings.trusted_domain_list,
        trusted_senders=settings.trusted_sender_list,
        sensitivity="balanced",
        scan_retention_days=settings.scan_retention_days,
        store_email_bodies=settings.store_email_bodies,
        mailbox_alert_threshold=settings.mailbox_alert_threshold,
    )


def _default_subscription(org_id: str) -> SubscriptionPlan:
    limits = {
        "starter": settings.starter_monthly_scan_limit,
        "team": settings.team_monthly_scan_limit,
        "business": settings.business_monthly_scan_limit,
        "enterprise": settings.enterprise_monthly_scan_limit,
    }
    plan = settings.default_plan if settings.default_plan in limits else "starter"
    return SubscriptionPlan(
        org_id=org_id,
        plan=plan,
        monthly_scan_limit=limits[plan],
        mailbox_accounts_limit=1 if plan == "starter" else 5 if plan == "team" else 50,
        retention_days_limit=30 if plan == "starter" else 90 if plan == "team" else 365,
        threat_intel_enabled=plan in {"business", "enterprise"} or settings.threat_intel_enabled,
        audit_log_enabled=True,
        billing_status="trial",
    )


def _monthly_period() -> tuple[datetime, datetime]:
    now = datetime.now(UTC)
    period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if period_start.month == 12:
        period_end = period_start.replace(year=period_start.year + 1, month=1)
    else:
        period_end = period_start.replace(month=period_start.month + 1)
    return period_start, period_end


def _count_scans(context: RequestContext, period_start: datetime, period_end: datetime) -> int:
    if not settings.database_enabled:
        return 0
    init_storage()
    with _connect() as connection:
        return connection.execute(
            """
            SELECT COUNT(*)
            FROM scan_events
            WHERE org_id = ? AND scanned_at >= ? AND scanned_at < ?
            """,
            (context.org_id, period_start.isoformat(), period_end.isoformat()),
        ).fetchone()[0]
