# AdaptiveScan Architecture

AdaptiveScan is positioned as a commercial attack surface management, exposure intelligence, continuous monitoring, and vulnerability assessment SaaS platform.

## Product Operating Model

The core customer workflow is:

1. Organization
2. Assets
3. Monitoring
4. Exposure
5. Findings
6. Reports

Scanner internals are kept behind product workflows. Customers manage owned assets, monitor drift, prioritize exposure, assign findings, and export executive or technical reports.

## Platform Layers

### Public Experience

- Marketing home, features, pricing, documentation, contact, trust, login, and registration.
- Trial-first onboarding that moves a buyer from account creation to first monitored asset.
- Trust center content for security, compliance, and privacy posture.

### SaaS Control Plane

- Organizations and workspaces define tenancy boundaries.
- RBAC roles govern access to exposure, telemetry, orchestration, and administration.
- MFA, OTP, JWT access tokens, refresh sessions, audit logs, and API keys form the identity foundation.
- Billing catalog and subscription status model trial, paid plans, usage, and entitlements.

### Exposure Data Plane

- Asset inventory tracks domains, APIs, services, certificates, technologies, cloud exposure candidates, and findings.
- Monitoring workflows track recurring discovery, drift, executive reporting, and retesting.
- Exposure intelligence ranks exploitable internet-facing risk.
- Attack path correlation connects exposed assets, weak auth, APIs, findings, and high-value targets.

### Execution Plane

- FastAPI exposes product APIs and operational APIs.
- Celery worker architecture is represented for distributed scan execution.
- Redis is the queue and ephemeral orchestration layer.
- Object storage stores report bundles, evidence, screenshots, and exported artifacts.
- PostgreSQL is the intended production persistence layer with Alembic migrations.

### Intelligence Plane

- Recon intelligence extracts JavaScript endpoints, source maps, secrets, admin routes, APIs, GraphQL, and auth signals.
- AI modules support risk prioritization, deduplication, exploitability prediction, attack path explanation, executive summaries, and remediation guidance.
- Provider abstraction supports local models and external providers.

## Commercial API Surface

- `/api/public-api/catalog`
- `/api/public/assets`
- `/api/public/findings`
- `/api/public/reports`
- `/api/public/monitoring`
- `/api/public/notifications`
- `/api/founder/analytics`
- `/api/marketplace/architecture`
- `/api/implementation/report`

## Enterprise Integrations

The marketplace architecture supports Slack, Microsoft Teams, Discord, Jira, GitHub, GitLab, ServiceNow, Splunk, Elastic, and Microsoft Sentinel through scoped connector manifests, webhook delivery, ticket creation, and audit logging.

## Security Controls

- MFA and OTP challenges
- JWT access tokens and refresh-session boundary
- RBAC permission checks
- Tenant-scoped organizations and workspaces
- API key management
- Audit logs
- Rate-limit-ready API boundary
- Scan authorization and allowlist controls
- Trust center alignment with SOC 2 readiness, ISO 27001 mapping, and OWASP evidence exports
