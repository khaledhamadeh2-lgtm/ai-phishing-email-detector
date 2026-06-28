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
  const [loading, setLoading] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [error, setError] = useState("");
  const [feedback, setFeedback] = useState("");
  const api = import.meta.env.VITE_API_URL || "http://localhost:8000";
  const tone = useMemo(() => (result ? riskClass(result.probability) : "neutral"), [result]);

  function tenantHeaders() {
    return { "X-Org-ID": workspace.orgId || "demo-org", "X-User-ID": workspace.userId || "anonymous" };
  }

  async function refreshProductState() {
    setHistoryLoading(true);
    try {
      const [settingsResponse, historyResponse, metricsResponse] = await Promise.all([
        fetch(`${api}/api/org/settings`, { headers: tenantHeaders() }),
        fetch(`${api}/api/scans/history?limit=8`, { headers: tenantHeaders() }),
        fetch(`${api}/api/dashboard/metrics`, { headers: tenantHeaders() }),
      ]);
      if (settingsResponse.ok) setSettings(await settingsResponse.json());
      if (historyResponse.ok) setHistory(await historyResponse.json());
      if (metricsResponse.ok) setMetrics(await metricsResponse.json());
    } finally {
      setHistoryLoading(false);
    }
  }

  useEffect(() => {
    void refreshProductState();
  }, [workspace.orgId]);

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
        <p>Hybrid ML, tenant-aware scan history, privacy-first settings, and safe threat-intel scaffolding.</p>
      </section>

      <section className="metrics-section panel">
        <div className="panel-title">
          <div><small>00 / PRODUCT METRICS</small><h2>{workspace.orgId || "demo-org"} dashboard</h2></div>
          <button className="ghost" type="button" onClick={refreshProductState}>{historyLoading ? "Refreshing..." : "Refresh"}</button>
        </div>
        <div className="metric-grid">
          <article><b>{metrics?.total_scans ?? 0}</b><span>Total scans</span></article>
          <article><b>{metrics?.likely_phishing_count ?? 0}</b><span>Likely phishing</span></article>
          <article><b>{metrics?.suspicious_count ?? 0}</b><span>Suspicious</span></article>
          <article><b>{metrics?.false_positive_count ?? 0}</b><span>False positives</span></article>
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

      <footer>This advisory tool stores redacted scan metadata by default, and never executes attachments or opens links.</footer>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
