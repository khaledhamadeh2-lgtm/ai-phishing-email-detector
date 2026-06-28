import sqlite3

from app.detector import analyze
from app.storage import RequestContext, init_storage, list_scan_history, record_scan


def test_scan_history_is_redacted_and_tenant_scoped(tmp_path, monkeypatch) -> None:
    database = tmp_path / "phishguard.sqlite3"
    monkeypatch.setattr("app.storage.settings.database_path", str(database))
    monkeypatch.setattr("app.storage.settings.database_enabled", True)
    monkeypatch.setattr("app.storage.settings.store_email_bodies", False)
    init_storage()

    result = analyze(
        "Maya <maya@example.org>",
        "Project notes",
        "The private launch code is alpha-123, but this body should not be stored.",
    )
    context = RequestContext(org_id="acme", user_id="maya")
    record_scan(
        context,
        "pasted",
        "Maya <maya@example.org>",
        "Project notes",
        "The private launch code is alpha-123, but this body should not be stored.",
        result,
    )

    acme_history = list_scan_history(context, limit=10)
    other_history = list_scan_history(RequestContext(org_id="other", user_id="analyst"), limit=10)

    assert len(acme_history) == 1
    assert other_history == []
    assert acme_history[0].org_id == "acme"
    assert acme_history[0].body_sha256

    with sqlite3.connect(database) as connection:
        row = connection.execute("SELECT body_preview FROM scan_events").fetchone()
    assert row[0] is None
