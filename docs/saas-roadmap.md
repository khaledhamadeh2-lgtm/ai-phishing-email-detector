# SaaS product roadmap

This project is currently a portfolio-ready phishing detector with the first SaaS foundation pieces in place. The
goal is to evolve it into a privacy-conscious email security service without pretending demo features are production
security controls.

## Implemented foundation

- Tenant-aware scan history using `X-Org-ID` and `X-User-ID` request context.
- Local signup/login with PBKDF2 password hashing, signed bearer tokens, organizations, owner role, and member listing.
- SQLite persistence for redacted scan events and feedback events.
- Workspace settings API for trusted domains, known senders, sensitivity, retention, and privacy mode.
- Dashboard metrics API for scan counts, verdict distribution, feedback counts, attachment counts, and top risks.
- `/api/me` auth context with role/permission shape for future auth provider integration.
- Gmail and Outlook OAuth connection endpoints with read-only scopes, short-lived state, connection status, and
  disconnect support. Provider authorization-code exchange is intentionally documented as the next production step.
- Subscription and usage-metering endpoints for plan limits, monthly scan quota, billing status, and future Stripe
  integration.
- Audit log endpoint for scans, feedback, settings changes, subscription changes, and compliance actions.
- Compliance export and tenant data deletion endpoints that operate on redacted scan metadata by default.
- Security posture endpoint that summarizes active controls and production launch gaps for operators.
- Threat-intelligence preview API that extracts domains and shows disabled provider scaffolding without external calls.
- Scan history stores sender, subject, verdict, score, top reasons, source, attachment count, and body hash.
- Full email bodies are not stored by default.
- Configurable retention window through `PHISHGUARD_SCAN_RETENTION_DAYS`.
- Docker Compose persists application state in a named volume.

SQLite is intentional for local demos. A paid/public deployment should move this schema to managed PostgreSQL.

## Next production steps

### 1. PostgreSQL

Move from local SQLite to managed PostgreSQL before public users:

- Add migrations.
- Add connection pooling.
- Add backups and restore testing.
- Add row-level tenant filtering in every query.
- Add retention cleanup as a scheduled job.

Recommended providers: Supabase, Neon, Render Postgres, Railway, Fly Postgres, or AWS RDS.

### 2. Production accounts and organizations

Upgrade local auth to production identity:

- Email verification, password reset, MFA, account lockout, and session revocation.
- Roles: owner, admin, analyst, viewer.
- Invitations and role changes.
- Per-organization trusted domains, known senders, retention policy, and mailbox integrations.

Recommended options: Clerk, Auth0, Supabase Auth, or a carefully implemented FastAPI auth service.

### 3. Gmail and Outlook OAuth

Public SaaS should not ask for mailbox passwords.

Use provider OAuth with least-privilege, read-only access:

- Gmail API with readonly scope.
- Microsoft Graph Mail.Read scope.
- Disconnect/revoke integration button.
- Clear permission explanation before connecting.
- Store refresh tokens encrypted using a managed secret/KMS service.
- Server-side code-to-token exchange and refresh-token rotation.
- Provider verification/approval flow before public launch.

The scanner should continue to avoid marking messages as read, moving messages, replying, deleting, or quarantining
without a separate explicit product feature and user consent.

### 4. Threat-intelligence checks

Add reputation checks without visiting submitted links in a browser:

- Google Safe Browsing.
- VirusTotal URL/domain hash lookups.
- URLhaus or PhishTank feeds.
- DNS/MX existence checks.
- Domain age and newly registered domain signals.

All external lookups should be privacy-reviewed because URLs can contain sensitive tokens.

### 5. Deployment

Practical low-cost deployment path:

- Frontend: Vercel, Netlify, or static hosting behind Cloudflare.
- Backend: Render, Fly.io, Railway, or AWS App Runner.
- Database: managed PostgreSQL.
- Secrets: platform secret manager only, never committed `.env`.
- Observability: structured logs, error monitoring, uptime checks.
- Security: HTTPS, strict CORS, API key/session auth, rate limits, dependency scanning, CodeQL.

### 6. Billing

Add billing only after accounts, orgs, and usage tracking are stable:

- Stripe checkout.
- Plans: Starter, Team, Business, Enterprise.
- Usage meters: scans/month, mailbox integrations, users per organization.
- Billing portal for cancellation and invoices.
- Webhook handling for subscription status changes.
- Grace period and soft-limit workflows before hard blocking security scans.

## Honest product limitations

- The detector is advisory and can be wrong.
- Static attachment analysis cannot prove a file is safe.
- Public datasets do not guarantee performance on a specific organization mailbox.
- Threat-intelligence APIs may leak submitted URL metadata to third parties unless carefully designed.
- OAuth integrations require provider approval, privacy review, and secure token storage.
