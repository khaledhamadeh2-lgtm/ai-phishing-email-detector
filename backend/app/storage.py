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
from .schemas import AnalysisResponse, DashboardMetrics, OrgSettings, ScanHistoryRecord


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
    return normalized


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
