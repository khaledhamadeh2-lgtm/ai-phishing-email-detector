import React, { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

type RiskFactor = { id: string; title: string; detail: string; severity: string; weight: number };
type Result = {
  probability: number;
  verdict: string;
  rule_score: number;
  model_score: number;
  risk_factors: RiskFactor[];
  highlights: { text: string; kind: string; explanation: string }[];
  recommendations: string[];
  model_version: string;
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

function App() {
  const [email, setEmail] = useState(samples.suspicious);
  const [result, setResult] = useState<Result | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const api = import.meta.env.VITE_API_URL || "http://localhost:8000";
  const tone = useMemo(() => {
    if (!result) return "neutral";
    return result.probability >= 70 ? "danger" : result.probability >= 35 ? "warning" : "safe";
  }, [result]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      const response = await fetch(`${api}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(email),
      });
      if (!response.ok) throw new Error("The analysis service could not process this message.");
      setResult(await response.json());
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
    const form = new FormData();
    form.append("file", file);
    try {
      const response = await fetch(`${api}/api/analyze-eml`, { method: "POST", body: form });
      if (!response.ok) throw new Error("Only readable, plain-text .eml files under the size limit are supported.");
      setResult(await response.json());
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Upload failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main>
      <header>
        <div className="brand"><span className="shield">P</span> PHISHGUARD <b>AI</b></div>
        <span className="status"><i /> Analysis engine ready</span>
      </header>

      <section className="hero">
        <p className="eyebrow">Explainable threat intelligence</p>
        <h1>Know before you <span>click.</span></h1>
        <p>Hybrid machine learning and security heuristics expose the signals hiding inside suspicious emails.</p>
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
            <button className="analyze" disabled={loading}>{loading ? "Analyzing…" : "Analyze message →"}</button>
          </div>
          {error && <p role="alert" className="error">{error}</p>}
        </form>

        <aside className={`panel report ${tone}`} aria-live="polite">
          {!result ? (
            <div className="empty">
              <div className="radar"><span /></div>
              <h2>Awaiting signal</h2>
              <p>Submit a message to map its risk indicators and receive an explainable verdict.</p>
            </div>
          ) : (
            <>
              <div className="panel-title"><div><small>02 / ASSESSMENT</small><h2>Threat report</h2></div><b className="verdict">{result.verdict}</b></div>
              <div className="score">
                <div><strong>{result.probability.toFixed(0)}</strong><span>%</span></div>
                <p>Phishing probability<small>ML {result.model_score}% · Rules {result.rule_score}%</small></p>
              </div>
              <div className="meter"><span style={{width: `${result.probability}%`}} /></div>
              <h3>Detected signals <span>{result.risk_factors.length}</span></h3>
              <div className="findings">
                {result.risk_factors.length ? result.risk_factors.map((factor) => (
                  <article key={factor.id}><i className={factor.severity}>!</i><div><b>{factor.title}</b><p>{factor.detail}</p></div><span>+{factor.weight}</span></article>
                )) : <p className="quiet">No strong rule-based risk indicators were detected.</p>}
              </div>
              <h3>Recommended response</h3>
              <ol>{result.recommendations.map((item) => <li key={item}>{item}</li>)}</ol>
              <small className="version">Model: {result.model_version}</small>
            </>
          )}
        </aside>
      </section>
      <footer>This advisory tool never opens links or attachments. Always verify sensitive requests through trusted security channels.</footer>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
