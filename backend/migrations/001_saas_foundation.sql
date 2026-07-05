-- PhishGuard AI SaaS foundation schema.
-- SQLite-compatible for local demos. For PostgreSQL, replace INTEGER PRIMARY KEY AUTOINCREMENT with
-- BIGSERIAL PRIMARY KEY and use TIMESTAMPTZ for timestamp fields.

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
);

CREATE INDEX IF NOT EXISTS idx_scan_events_org_time ON scan_events(org_id, scanned_at DESC);

CREATE TABLE IF NOT EXISTS feedback_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    label TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_feedback_events_analysis ON feedback_events(analysis_id);

CREATE TABLE IF NOT EXISTS org_settings (
    org_id TEXT PRIMARY KEY,
    trusted_domains_json TEXT NOT NULL,
    trusted_senders_json TEXT NOT NULL,
    sensitivity TEXT NOT NULL,
    scan_retention_days INTEGER NOT NULL,
    store_email_bodies INTEGER NOT NULL,
    mailbox_alert_threshold REAL NOT NULL,
    updated_at TEXT NOT NULL
);

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
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_org_time
ON audit_events(org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS organizations (
    org_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS organization_members (
    org_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL,
    joined_at TEXT NOT NULL,
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id) REFERENCES organizations(org_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE INDEX IF NOT EXISTS idx_org_members_user
ON organization_members(user_id);

CREATE TABLE IF NOT EXISTS oauth_states (
    state TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mailbox_integrations (
    org_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    account_email TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    encrypted_token_json TEXT NOT NULL,
    connected_at TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (org_id, provider)
);
