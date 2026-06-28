import hashlib
import json
import sqlite3
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .config import settings
from .schemas import AnalysisResponse, ScanHistoryRecord


@dataclass(frozen=True)
class RequestContext:
    org_id: str = "demo-org"
    user_id: str = "anonymous"


def normalize_context(org_id: str = "", user_id: str = "") -> RequestContext:
    return RequestContext(
        org_id=(org_id or "demo-org").strip()[:120],
        user_id=(user_id or "anonymous").strip()[:120],
    )


@contextmanager
def _connect():
    path = Path(settings.database_path)
    if str(path).replace("\\", "/").startswith("/tmp/"):
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
