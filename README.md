# PhishGuard AI

An explainable, portfolio-grade phishing email detector that combines a trained text classifier with deterministic
security rules. It accepts pasted messages and `.eml` files, assigns a 0–100% phishing probability, and shows the
signals behind its verdict—without visiting links or opening attachments.

> **Advisory only:** PhishGuard can be wrong. Do not use it as the sole basis for a security decision.

## Why this project

Black-box predictions are awkward in security. PhishGuard pairs TF-IDF logistic regression with transparent checks
for credential requests, urgency, risky payments, sender impersonation, URL shorteners, raw-IP links, suspicious
top-level domains, and malformed senders. Users see both component scores and concrete recommended actions.

## Demo

Run the project and open [http://localhost:8080](http://localhost:8080). The interface includes safe and suspicious
inert samples for a quick recruiter-friendly demonstration.

```bash
docker compose up --build
```

## Architecture

```mermaid
flowchart LR
    UI["React dashboard"] -->|JSON or EML| API["FastAPI validation layer"]
    API --> Parser["Safe MIME text parser"]
    API --> Rules["Explainable rule engine"]
    API --> ML["TF-IDF + logistic regression"]
    Parser --> Rules
    Parser --> ML
    Rules --> Fusion["Weighted risk fusion"]
    ML --> Fusion
    Fusion --> Report["Probability, verdict, evidence, actions"]
    Report --> UI
```

## Detection methodology

- **Rules (42%):** high-signal, auditable indicators such as credential language, pressure, payment requests,
  brand/free-mail mismatches, suspicious URL structure, and aggressive formatting.
- **Model (58%):** a scikit-learn pipeline using word and bigram TF-IDF features with class-weighted logistic
  regression. Logistic regression is fast, inspectable, and produces calibrated-enough ranking for this demo.
- **Fusion:** bounded weighted scoring maps to `Safe` (<35), `Suspicious` (35–69.9), or `Likely Phishing` (≥70).

The parser reads only plain-text MIME parts, skips attachments, caps input size, and never performs network requests.

## Model evaluation

The repository ships a versioned model trained on a tiny, inert synthetic dataset so every clone is immediately
reproducible. The generated `docs/model-metrics.json` values are **smoke-test metrics, not an accuracy claim**.
A credible benchmark requires a larger, current, deduplicated corpus and group-aware splitting by campaign/source.

The training pipeline supports local CSV data with `text,label` columns. Recommended primary sources and licensing
notes are documented in [`ml/README.md`](ml/README.md). Exact duplicates are removed before the stratified split.
Recall is favored using phishing class weighting, accepting a potential increase in false positives.

```bash
python ml/train.py --dataset path/to/local_dataset.csv
```

## API

Interactive OpenAPI documentation is available at [http://localhost:8000/docs](http://localhost:8000/docs).

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"sender":"Maya <maya@example.org>","subject":"Notes","body":"See you Thursday."}'
```

`POST /api/analyze-eml` accepts multipart field `file`. Only `.eml` uploads are allowed; attachments are ignored.

## Local development

Backend:

```bash
cd backend
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest --cov=app
uvicorn app.main:app --reload
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Copy `.env.example` to `.env` only when overriding defaults. Never commit real email, credentials, or secrets.

## Security and privacy

- Links are extracted as strings only; the application does not resolve, fetch, or render them.
- Attachments and HTML MIME parts are ignored.
- Input is validated and size-limited; errors avoid echoing submitted email content into logs.
- The demo has no database and retains no messages.
- Production use should add authentication, TLS, rate limits, malware isolation, redaction, and a documented
  retention policy.

## Tests and automation

GitHub Actions runs Ruff, pytest with an 80% coverage floor, `pip-audit`, the TypeScript production build, and Docker
Compose builds. Run the main checks locally:

```bash
cd backend && ruff check app tests ../ml && pytest --cov=app --cov-fail-under=80
cd ../frontend && npm run build
docker compose build
```

## Limitations and future work

- The bundled model is a reproducible demonstration, not a production benchmark.
- Text-only analysis cannot inspect images, QR codes, attachment contents, or live domain reputation.
- Sender display names are not proof of identity; full SPF, DKIM, and DMARC results require trusted mail headers.
- Attackers can evade lexical models through obfuscation, new languages, and novel social-engineering tactics.
- Future work: campaign-grouped evaluation, multilingual models, SHAP-style feature explanations, authenticated
  analyst feedback, domain reputation through a privacy-conscious service, and drift monitoring.

## What I learned

This project strengthened my ability to turn an ML experiment into a usable security product: safe MIME parsing,
explainable scoring, leakage-aware evaluation, typed API design, accessible UI work, containerization, and CI
security checks. The most important lesson was that honest uncertainty and useful explanations matter as much as a
headline accuracy number.

## CV-ready description

- Built an explainable phishing-email detector combining TF-IDF logistic regression with a weighted cybersecurity
  rule engine and human-readable risk evidence.
- Designed a typed FastAPI service and responsive React dashboard supporting pasted email and safe `.eml` analysis.
- Implemented reproducible training, leakage controls, model versioning, pytest coverage, dependency auditing,
  Docker Compose, and GitHub Actions CI.
- Applied privacy-by-design controls that prevent URL fetching, ignore attachments, validate input, and retain no
  submitted messages.

## License

MIT
