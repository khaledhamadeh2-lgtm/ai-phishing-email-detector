# Deployment guide

This guide describes a realistic low-cost path from portfolio demo to public SaaS.

## Recommended architecture

- Frontend: Vercel, Netlify, or Cloudflare Pages.
- Backend API: Render, Fly.io, Railway, or AWS App Runner.
- Database: managed PostgreSQL such as Supabase, Neon, Render Postgres, Railway Postgres, or RDS.
- Secrets: platform secret manager only.
- DNS/TLS: managed HTTPS with a custom domain.

## Minimum production environment

```bash
PHISHGUARD_ALLOWED_ORIGINS=https://your-frontend.example
PHISHGUARD_API_KEY=<strong-random-api-key-or-replace-with-real-auth>
PHISHGUARD_DATABASE_ENABLED=true
PHISHGUARD_DATABASE_URL=postgresql://user:password@host:5432/phishguard
PHISHGUARD_STORE_EMAIL_BODIES=false
PHISHGUARD_SCAN_RETENTION_DAYS=30
PHISHGUARD_AUTH_MODE=provider
PHISHGUARD_DEFAULT_PLAN=starter
PHISHGUARD_ENFORCE_PLAN_LIMITS=false
PHISHGUARD_THREAT_INTEL_ENABLED=false
```

The current code uses SQLite locally. The schema is documented in
`backend/migrations/001_saas_foundation.sql`; production should move to PostgreSQL migrations before accepting real
users.

## Launch checklist

- Replace demo tenant headers with real authentication.
- Add account email verification and password reset.
- Add org roles: owner, admin, analyst, viewer.
- Migrate scan and settings tables to PostgreSQL.
- Enable TLS and strict CORS.
- Configure uptime monitoring.
- Configure error monitoring.
- Define data retention and deletion flows.
- Review `/api/security/posture` before launch and close every high-priority gap.
- Decide whether plan limits should soft-warn or hard-block scans before setting
  `PHISHGUARD_ENFORCE_PLAN_LIMITS=true`.
- Connect `/api/billing/subscription` to Stripe or another billing system instead of manually updating plans.
- Include `/api/audit/events` in support/admin workflows so sensitive configuration changes are traceable.
- Add provider-specific privacy notices for threat-intelligence APIs.
- Add billing only after usage tracking and org membership are stable.

## Gmail and Outlook integration notes

Public SaaS should not ask for mailbox passwords.

- Gmail: use OAuth and read-only Gmail API scopes.
- Outlook/Microsoft 365: use Microsoft Graph `Mail.Read` with admin-consent support for organizations.
- Store refresh tokens encrypted using a managed KMS/secret system.
- Provide a disconnect button that revokes integration state.
- Keep scanning read-only until quarantine workflows are separately designed and consented.

## Threat intelligence provider notes

Safe future providers:

- Google Safe Browsing.
- VirusTotal URL/domain hash workflows.
- URLhaus feeds.
- PhishTank/OpenPhish feeds.
- DNS/MX/domain-age signals.

Do not silently send full URLs to third parties. URLs can contain private tokens, user IDs, and document links.
