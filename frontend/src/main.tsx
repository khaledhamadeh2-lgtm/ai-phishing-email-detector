import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

type RiskFactor = { id: string; title: string; detail: string; severity: string; weight: number };
type TrustSignal = { title: string; detail: string; adjustment: number };
type AttachmentFinding = {
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  risk_level: string;
  reasons: string[];
  score: number;
};
type Result = {
  analysis_id: string;
  probability: number;
  verdict: string;
  rule_score: number;
  model_score: number;
  risk_factors: RiskFactor[];
  trust_signals: TrustSignal[];
  attachments: AttachmentFinding[];
  recommendations: string[];
  model_version: string;
  sensitivity: string;
  suspicious_threshold: number;
  likely_phishing_threshold: number;
};
type ScanRecord = {
  analysis_id: string;
  org_id: string;
  user_id: string;
  source: string;
  scanned_at: string;
  sender: string;
  subject: string;
  probability: number;
  verdict: string;
  risk_factors: string[];
  attachment_count: number;
  body_sha256: string;
};
type Metrics = {
  org_id: string;
  total_scans: number;
  safe_count: number;
  suspicious_count: number;
  likely_phishing_count: number;
  attachment_scan_count: number;
  feedback_count: number;
  false_positive_count: number;
  top_risk_factors: { title: string; count: number }[];
};
type OrgSettings = {
  org_id: string;
  trusted_domains: string[];
  trusted_senders: string[];
  sensitivity: string;
  scan_retention_days: number;
  store_email_bodies: boolean;
  mailbox_alert_threshold: number;
};
type ThreatIntelPreview = {
  enabled: boolean;
  domains: string[];
  findings: { provider: string; status: string; detail: string }[];
  privacy_note: string;
};
type Subscription = {
  org_id: string;
  plan: string;
  monthly_scan_limit: number;
  mailbox_accounts_limit: number;
  retention_days_limit: number;
  threat_intel_enabled: boolean;
  audit_log_enabled: boolean;
  billing_status: string;
};
type UsageSummary = {
  org_id: string;
  plan: string;
  scans_used: number;
  monthly_scan_limit: number;
  scans_remaining: number;
  usage_percent: number;
  limit_enforced: boolean;
};
type AuditEvent = {
  event_id: number;
  user_id: string;
  action: string;
  target: string;
  created_at: string;
};
type SecurityPosture = {
  api_key_required: boolean;
  auth_mode: string;
  database_enabled: boolean;
  store_email_bodies: boolean;
  threat_intel_enabled: boolean;
  rate_limit: string;
  controls: string[];
  recommended_next_steps: string[];
};
type CurrentUser = {
  org_id: string;
  user_id: string;
  email: string;
  role: string;
  auth_mode: string;
};
type Organization = {
  org_id: string;
  name: string;
  role: string;
  members: { user_id: string; email: string; role: string; joined_at: string }[];
};
type MailboxIntegration = {
  provider: string;
  connected: boolean;
  account_email: string;
  scopes: string[];
  connected_at: string;
  status: string;
  privacy_note: string;
};

const samples = {
  suspicious: {
    sender: "Microsoft Support <security.microsoft@gmail.com>",
    subject: "URGENT: Account suspended",
    body: "Dear customer,\n\nYour mailbox will be disabled within 2 hours. Verify your password immediately at https://198.51.100.10/login!!!!\n\nSupport Team",
  },
  safe: {
    sender: "Maya Chen <maya@example.org>",
    subject: "Updated project notes",
    body: "Hi team,\n\nI added the decisions from today's planning meeting to our usual shared workspace. We can review them Thursday.\n\nMaya",
  },
};

function riskClass(probability: number) {
  return probability >= 70 ? "danger" : probability >= 35 ? "warning" : "safe";
}

function splitList(value: string) {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function joinList(value: string[]) {
  return value.join(", ");
}

function App() {
  const [email, setEmail] = useState(samples.suspicious);
  const [workspace, setWorkspace] = useState({ orgId: "demo-org", userId: "analyst-demo" });
  const [settings, setSettings] = useState<OrgSettings>({
    org_id: "demo-org",
    trusted_domains: ["example.org", "trustedvendor.com"],
    trusted_senders: [],
    sensitivity: "balanced",
    scan_retention_days: 30,
    store_email_bodies: false,
    mailbox_alert_threshold: 70,
  });
  const [result, setResult] = useState<Result | null>(null);
  const [history, setHistory] = useState<ScanRecord[]>([]);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [intel, setIntel] = useState<ThreatIntelPreview | null>(null);
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [usage, setUsage] = useState<UsageSummary | null>(null);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [posture, setPosture] = useState<SecurityPosture | null>(null);
  const [token, setToken] = useState(() => localStorage.getItem("phishguard_token") || "");
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null);
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [integrations, setIntegrations] = useState<MailboxIntegration[]>([]);
  const [authForm, setAuthForm] = useState({
    email: "owner@demo.test",
    password: "correct horse battery staple",
    organizationName: "Demo Security Team",
  });
  const [loading, setLoading] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [error, setError] = useState("");
  const [feedback, setFeedback] = useState("");
  const api = import.meta.env.VITE_API_URL || "http://localhost:8000";
  const tone = useMemo(() => (result ? riskClass(result.probability) : "neutral"), [result]);

  function tenantHeaders() {
    const headers: Record<string, string> = {
      "X-Org-ID": workspace.orgId || "demo-org",
      "X-User-ID": workspace.userId || "anonymous",
    };
    if (token) headers.Authorization = `Bearer ${token}`;
    return headers;
  }

  async function refreshProductState() {
    setHistoryLoading(true);
    try {
      const [
        settingsResponse,
        historyResponse,
        metricsResponse,
        subscriptionResponse,
        usageResponse,
        auditResponse,
        postureResponse,
        meResponse,
        orgResponse,
        integrationsResponse,
      ] = await Promise.all([
        fetch(`${api}/api/org/settings`, { headers: tenantHeaders() }),
        fetch(`${api}/api/scans/history?limit=8`, { headers: tenantHeaders() }),
        fetch(`${api}/api/dashboard/metrics`, { headers: tenantHeaders() }),
        fetch(`${api}/api/billing/subscription`, { headers: tenantHeaders() }),
        fetch(`${api}/api/billing/usage`, { headers: tenantHeaders() }),
        fetch(`${api}/api/audit/events?limit=6`, { headers: tenantHeaders() }),
        fetch(`${api}/api/security/posture`, { headers: tenantHeaders() }),
        fetch(`${api}/api/me`, { headers: tenantHeaders() }),
        fetch(`${api}/api/org`, { headers: tenantHeaders() }),
        fetch(`${api}/api/oauth/integrations`, { headers: tenantHeaders() }),
      ]);
      if (settingsResponse.ok) setSettings(await settingsResponse.json());
      if (historyResponse.ok) setHistory(await historyResponse.json());
      if (metricsResponse.ok) setMetrics(await metricsResponse.json());
      if (subscriptionResponse.ok) setSubscription(await subscriptionResponse.json());
      if (usageResponse.ok) setUsage(await usageResponse.json());
      if (auditResponse.ok) setAudit(await auditResponse.json());
      if (postureResponse.ok) setPosture(await postureResponse.json());
      if (meResponse.ok) setCurrentUser(await meResponse.json());
      if (orgResponse.ok) setOrganization(await orgResponse.json());
      if (integrationsResponse.ok) setIntegrations(await integrationsResponse.json());
    } finally {
      setHistoryLoading(false);
    }
  }

  useEffect(() => {
    void refreshProductState();
  }, [workspace.orgId, token]);

  async function saveSettings() {
    const response = await fetch(`${api}/api/org/settings`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", ...tenantHeaders() },
      body: JSON.stringify({ ...settings, org_id: workspace.orgId || "demo-org" }),
    });
    if (!response.ok) {
      setError("Settings could not be saved.");
      return;
    }
    setSettings(await response.json());
    setFeedback("Settings saved for this workspace.");
  }

  async function authenticate(mode: "signup" | "login") {
    setError("");
    setFeedback("");
    const payload = mode === "signup"
      ? { email: authForm.email, password: authForm.password, organization_name: authForm.organizationName }
      : { email: authForm.email, password: authForm.password };
    try {
      const response = await fetch(`${api}/api/auth/${mode}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) throw new Error(mode === "signup" ? "Signup failed." : "Login failed.");
      const data = await response.json();
      localStorage.setItem("phishguard_token", data.access_token);
      setToken(data.access_token);
      setCurrentUser(data.user);
      setWorkspace({ orgId: data.user.org_id, userId: data.user.user_id });
      setFeedback(`${mode === "signup" ? "Workspace created" : "Logged in"} as ${data.user.email}.`);
      await refreshProductState();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Authentication failed.");
    }
  }

  function logout() {
    localStorage.removeItem("phishguard_token");
    setToken("");
    setCurrentUser(null);
    setOrganization(null);
    setIntegrations([]);
    setFeedback("Logged out. Demo headers are active again.");
  }

  async function connectMailbox(provider: "gmail" | "outlook") {
    setError("");
    setFeedback("");
    try {
      const response = await fetch(`${api}/api/oauth/${provider}/connect`, { headers: tenantHeaders() });
      if (!response.ok) throw new Error(`Could not start ${provider} OAuth.`);
      const data = await response.json();
      setFeedback(`${provider} OAuth URL generated. In production this opens provider consent.`);
      window.open(data.authorization_url, "_blank", "noopener,noreferrer");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "OAuth connection failed.");
    }
  }

  async function disconnectMailbox(provider: string) {
    setError("");
    const response = await fetch(`${api}/api/oauth/${provider}`, {
      method: "DELETE",
      headers: tenantHeaders(),
    });
    if (!response.ok) {
      setError(`Could not disconnect ${provider}.`);
      return;
    }
    setFeedback(`${provider} disconnected.`);
    await refreshProductState();
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setFeedback("");
    try {
      const payload = {
        ...email,
        trusted_domains: settings.trusted_domains,
        trusted_senders: settings.trusted_senders,
        sensitivity: settings.sensitivity,
      };
      const [analysisResponse, intelResponse] = await Promise.all([
        fetch(`${api}/api/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...tenantHeaders() },
          body: JSON.stringify(payload),
        }),
        fetch(`${api}/api/threat-intel/preview`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...tenantHeaders() },
          body: JSON.stringify(payload),
        }),
      ]);
      if (!analysisResponse.ok) throw new Error("The analysis service could not process this message.");
      setResult(await analysisResponse.json());
      if (intelResponse.ok) setIntel(await intelResponse.json());
      await refreshProductState();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Analysis failed.");
    } finally {
      setLoading(false);
    }
  }

  async function upload(file?: File) {
    if (!file) return;
    setLoading(true);
    setError("");
    setFeedback("");
    const form = new FormData();
    form.append("file", file);
    try {
      const response = await fetch(`${api}/api/analyze-eml`, {
        method: "POST",
        headers: tenantHeaders(),
        body: form,
      });
      if (!response.ok) throw new Error("Only readable .eml files under the size limit are supported.");
      setResult(await response.json());
      await refreshProductState();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Upload failed.");
    } finally {
      setLoading(false);
    }
  }

  async function sendFeedback(
    label: "false_positive" | "false_negative" | "safe" | "phishing",
    analysisId = result?.analysis_id,
  ) {
    if (!analysisId) return;
    setFeedback("");
    try {
      const response = await fetch(`${api}/api/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...tenantHeaders() },
        body: JSON.stringify({ analysis_id: analysisId, label, note: "" }),
      });
      if (!response.ok) throw new Error("Feedback could not be saved.");
      setFeedback("Thanks — saved for future tuning.");
      await refreshProductState();
    } catch (caught) {
      setFeedback(caught instanceof Error ? caught.message : "Feedback failed.");
    }
  }

  return (
    <main>
      <header>
        <div className="brand"><span className="shield">P</span> PHISHGUARD <b>AI</b></div>
        <span className="status"><i /> Product dashboard ready</span>
      </header>

      <section className="hero">
        <p className="eyebrow">Explainable threat intelligence</p>
        <h1>Know before you <span>click.</span></h1>
        <p>Hybrid ML, real workspace auth, tenant-aware scan history, and read-only Gmail/Outlook connection scaffolding.</p>
      </section>

      <section className="identity-section panel">
        <div className="panel-title">
          <div><small>00 / ACCOUNT & INTEGRATIONS</small><h2>{currentUser ? organization?.name ?? currentUser.org_id : "Create a workspace"}</h2></div>
          {currentUser ? <button className="ghost" type="button" onClick={logout}>Log out</button> : null}
        </div>
        <div className="identity-grid">
          <article>
            <h3>{currentUser ? "Signed in" : "Local product auth"}</h3>
            {currentUser ? (
              <p className="quiet">{currentUser.email} · {currentUser.role} · {currentUser.auth_mode}</p>
            ) : (
              <>
                <label>Email<input value={authForm.email} onChange={(e) => setAuthForm({...authForm, email: e.target.value})} /></label>
                <label>Password<input type="password" value={authForm.password} onChange={(e) => setAuthForm({...authForm, password: e.target.value})} /></label>
                <label>Organization<input value={authForm.organizationName} onChange={(e) => setAuthForm({...authForm, organizationName: e.target.value})} /></label>
                <div className="actions compact">
                  <button className="analyze" type="button" onClick={() => authenticate("signup")}>Create workspace</button>
                  <button className="ghost" type="button" onClick={() => authenticate("login")}>Log in</button>
                </div>
              </>
            )}
          </article>
          <article>
            <h3>Organization</h3>
            <p className="quiet">{organization?.members.length ?? 0} member(s). Roles are ready for owner/admin/analyst/viewer workflows.</p>
            <div className="reason-chips">{organization?.members.slice(0, 4).map((member) => <em key={member.user_id}>{member.email}: {member.role}</em>)}</div>
          </article>
          <article>
            <h3>Read-only mailbox OAuth</h3>
            <p className="quiet">Generates Gmail/Microsoft consent URLs and stores connection state without sending, deleting, or modifying mail.</p>
            <div className="oauth-actions">
              <button type="button" onClick={() => connectMailbox("gmail")}>Connect Gmail</button>
              <button type="button" onClick={() => connectMailbox("outlook")}>Connect Outlook</button>
            </div>
            <div className="integration-list">
              {integrations.length ? integrations.map((item) => (
                <p key={item.provider}>
                  <b>{item.provider}</b>
                  <span>{item.status}</span>
                  <button type="button" onClick={() => disconnectMailbox(item.provider)}>Disconnect</button>
                </p>
              )) : <p className="quiet">No mailbox provider connected yet.</p>}
            </div>
          </article>
        </div>
      </section>

      <section className="metrics-section panel">
        <div className="panel-title">
          <div><small>00 / PRODUCT CONTROL PLANE</small><h2>{workspace.orgId || "demo-org"} dashboard</h2></div>
          <button className="ghost" type="button" onClick={refreshProductState}>{historyLoading ? "Refreshing..." : "Refresh"}</button>
        </div>
        <div className="metric-grid">
          <article><b>{metrics?.total_scans ?? 0}</b><span>Total scans</span></article>
          <article><b>{metrics?.likely_phishing_count ?? 0}</b><span>Likely phishing</span></article>
          <article><b>{metrics?.suspicious_count ?? 0}</b><span>Suspicious</span></article>
          <article><b>{metrics?.false_positive_count ?? 0}</b><span>False positives</span></article>
        </div>
        <div className="business-grid">
          <article>
            <small>PLAN</small>
            <b>{subscription?.plan ?? "starter"}</b>
            <span>{subscription?.billing_status ?? "trial"} · {usage?.scans_remaining ?? 0} scans left</span>
          </article>
          <article>
            <small>USAGE</small>
            <b>{usage?.usage_percent ?? 0}%</b>
            <span>{usage?.scans_used ?? 0} / {usage?.monthly_scan_limit ?? subscription?.monthly_scan_limit ?? 250} monthly scans</span>
            <div className="usage-bar"><i style={{width: `${Math.min(usage?.usage_percent ?? 0, 100)}%`}} /></div>
          </article>
          <article>
            <small>SECURITY</small>
            <b>{posture?.api_key_required ? "Locked" : "Demo"}</b>
            <span>{posture?.auth_mode ?? "demo-headers"} · {posture?.rate_limit ?? "rate limited"}</span>
          </article>
        </div>
        {!!metrics?.top_risk_factors.length && <div className="reason-chips metric-risks">{metrics.top_risk_factors.map((item) => <em key={item.title}>{item.title}: {item.count}</em>)}</div>}
      </section>

      <section className="workspace">
        <form className="panel composer" onSubmit={submit}>
          <div className="panel-title">
            <div><small>01 / INPUT</small><h2>Inspect a message</h2></div>
            <div className="samples">
              <button type="button" onClick={() => setEmail(samples.safe)}>Safe sample</button>
              <button type="button" onClick={() => setEmail(samples.suspicious)}>Phishing sample</button>
            </div>
          </div>
          <label>Sender<input value={email.sender} onChange={(e) => setEmail({...email, sender: e.target.value})} /></label>
          <label>Subject<input value={email.subject} onChange={(e) => setEmail({...email, subject: e.target.value})} /></label>
          <label>Message<textarea rows={10} required value={email.body} onChange={(e) => setEmail({...email, body: e.target.value})} /></label>
          <div className="actions">
            <label className="upload">Upload .eml<input type="file" accept=".eml,message/rfc822" onChange={(e) => upload(e.target.files?.[0])} /></label>
            <button className="analyze" disabled={loading}>{loading ? "Analyzing..." : "Analyze message →"}</button>
          </div>
          {error && <p role="alert" className="error">{error}</p>}
        </form>

        <section className="panel tuning">
          <div className="panel-title">
            <div><small>02 / SETTINGS</small><h2>Workspace settings</h2></div>
            <button className="ghost" type="button" onClick={saveSettings}>Save</button>
          </div>
          <p className="quiet">Demo tenant headers simulate accounts now; production auth can replace this cleanly.</p>
          <label>Organization ID<input value={workspace.orgId} onChange={(e) => setWorkspace({...workspace, orgId: e.target.value})} /></label>
          <label>User ID<input value={workspace.userId} onChange={(e) => setWorkspace({...workspace, userId: e.target.value})} /></label>
          <label>Trusted domains<input value={joinList(settings.trusted_domains)} onChange={(e) => setSettings({...settings, trusted_domains: splitList(e.target.value)})} /></label>
          <label>Known senders<input placeholder="maya@example.org, billing@vendor.com" value={joinList(settings.trusted_senders)} onChange={(e) => setSettings({...settings, trusted_senders: splitList(e.target.value)})} /></label>
          <label>Sensitivity<select value={settings.sensitivity} onChange={(e) => setSettings({...settings, sensitivity: e.target.value})}>
            <option value="balanced">Balanced</option>
            <option value="recall">Catch more phishing</option>
            <option value="precision">Reduce false positives</option>
          </select></label>
          <label>Retention days<input type="number" min={1} max={365} value={settings.scan_retention_days} onChange={(e) => setSettings({...settings, scan_retention_days: Number(e.target.value)})} /></label>
          <label>Mailbox alert threshold<input type="number" min={0} max={100} value={settings.mailbox_alert_threshold} onChange={(e) => setSettings({...settings, mailbox_alert_threshold: Number(e.target.value)})} /></label>
          <label className="check"><input type="checkbox" checked={settings.store_email_bodies} onChange={(e) => setSettings({...settings, store_email_bodies: e.target.checked})} /> Store email body previews</label>
        </section>

        <aside className={`panel report ${tone}`} aria-live="polite">
          {!result ? (
            <div className="empty"><div className="radar"><span /></div><h2>Awaiting signal</h2><p>Submit a message to map its risk indicators and receive an explainable verdict.</p></div>
          ) : (
            <>
              <div className="panel-title"><div><small>03 / ASSESSMENT</small><h2>Threat report</h2></div><b className="verdict">{result.verdict}</b></div>
              <div className="score"><div><strong>{result.probability.toFixed(0)}</strong><span>%</span></div><p>Phishing probability<small>ML {result.model_score}% · Rules {result.rule_score}% · {result.sensitivity}</small></p></div>
              <div className="thresholds"><span>Suspicious ≥ {result.suspicious_threshold}%</span><span>Likely phishing ≥ {result.likely_phishing_threshold}%</span></div>
              <div className="meter"><span style={{width: `${result.probability}%`}} /></div>
              {!!result.trust_signals.length && <><h3>Organization context <span>{result.trust_signals.length}</span></h3><div className="findings trust-list">{result.trust_signals.map((signal) => <article key={signal.title}><i className="trust">✓</i><div><b>{signal.title}</b><p>{signal.detail}</p></div><span>{signal.adjustment}</span></article>)}</div></>}
              <h3>Detected signals <span>{result.risk_factors.length}</span></h3>
              <div className="findings">{result.risk_factors.length ? result.risk_factors.map((factor) => <article key={factor.id}><i className={factor.severity}>!</i><div><b>{factor.title}</b><p>{factor.detail}</p></div><span>+{factor.weight}</span></article>) : <p className="quiet">No strong rule-based risk indicators were detected.</p>}</div>
              {!!result.attachments.length && <><h3>Attachment triage <span>{result.attachments.length}</span></h3><div className="findings">{result.attachments.map((attachment) => <article key={attachment.sha256}><i className={attachment.risk_level}>{attachment.risk_level === "low" ? "i" : "!"}</i><div><b>{attachment.filename}</b><p>{attachment.reasons.join(" ")}</p><small>{attachment.content_type} · {(attachment.size_bytes / 1024).toFixed(1)} KB · hash {attachment.sha256.slice(0, 12)}...</small></div><span>+{attachment.score}</span></article>)}</div></>}
              {!!intel && <><h3>Threat intel preview <span>{intel.domains.length}</span></h3><div className="findings">{intel.findings.map((finding) => <article key={`${finding.provider}-${finding.status}`}><i className="low">i</i><div><b>{finding.provider}</b><p>{finding.detail}</p></div><span>{finding.status}</span></article>)}</div><p className="privacy-note">{intel.privacy_note}</p></>}
              <h3>Recommended response</h3>
              <ol>{result.recommendations.map((item) => <li key={item}>{item}</li>)}</ol>
              <h3>Improve this detector</h3>
              <div className="feedback-actions">
                <button type="button" onClick={() => sendFeedback("false_positive")}>False positive</button>
                <button type="button" onClick={() => sendFeedback("false_negative")}>Missed phish</button>
                <button type="button" onClick={() => sendFeedback("safe")}>Correct safe</button>
                <button type="button" onClick={() => sendFeedback("phishing")}>Correct phish</button>
              </div>
              {feedback && <p className="feedback-note">{feedback}</p>}
              <small className="version">Model: {result.model_version}</small>
            </>
          )}
        </aside>
      </section>

      <section className="history-section panel">
        <div className="panel-title">
          <div><small>04 / SAAS HISTORY</small><h2>Recent scans for {workspace.orgId || "demo-org"}</h2></div>
          <button className="ghost" type="button" onClick={refreshProductState}>{historyLoading ? "Refreshing..." : "Refresh"}</button>
        </div>
        <p className="privacy-note">Stores sender, subject, score, verdict, reasons, source, attachment count, and body hash only — never full email bodies by default.</p>
        <div className="history-grid">
          {history.length ? history.map((item) => (
            <article className={`history-card ${riskClass(item.probability)}`} key={`${item.analysis_id}-${item.scanned_at}`}>
              <div className="history-top"><b>{item.verdict}</b><span>{item.probability.toFixed(0)}%</span></div>
              <h3>{item.subject || "(No subject)"}</h3>
              <p>{item.sender}</p>
              <small>{new Date(item.scanned_at).toLocaleString()} · {item.source} · Attachments: {item.attachment_count}</small>
              <div className="reason-chips">{item.risk_factors.length ? item.risk_factors.map((reason) => <em key={reason}>{reason}</em>) : <em>No strong rule signals</em>}</div>
              <div className="mini-feedback">
                <button type="button" onClick={() => sendFeedback("false_positive", item.analysis_id)}>False positive</button>
                <button type="button" onClick={() => sendFeedback("phishing", item.analysis_id)}>Correct phish</button>
              </div>
            </article>
          )) : <p className="quiet">No persisted scan history yet. Analyze a message to populate this tenant dashboard.</p>}
        </div>
      </section>

      <section className="ops-section panel">
        <div className="panel-title">
          <div><small>05 / SECURITY OPERATIONS</small><h2>Audit, compliance, and launch readiness</h2></div>
        </div>
        <div className="ops-grid">
          <article>
            <h3>Active controls</h3>
            <ul>{(posture?.controls ?? []).slice(0, 5).map((item) => <li key={item}>{item}</li>)}</ul>
          </article>
          <article>
            <h3>Next launch steps</h3>
            <ul>{(posture?.recommended_next_steps ?? []).slice(0, 5).map((item) => <li key={item}>{item}</li>)}</ul>
          </article>
          <article>
            <h3>Recent audit events</h3>
            <div className="audit-list">
              {audit.length ? audit.map((event) => (
                <p key={event.event_id}>
                  <b>{event.action}</b>
                  <span>{event.user_id} · {new Date(event.created_at).toLocaleString()}</span>
                </p>
              )) : <p className="quiet">No audit events yet. Save settings or scan a message to populate the trail.</p>}
            </div>
          </article>
        </div>
      </section>

      <footer>This advisory tool stores redacted scan metadata by default, and never executes attachments or opens links.</footer>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
