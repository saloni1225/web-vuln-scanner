# AdaptiveScan Production Platform Implementation

AdaptiveScan is now structured as an AI-assisted continuous attack surface and application security intelligence platform. The current implementation keeps the existing FastAPI, React, scanner, report, and SQLite workflows intact while adding production-oriented subsystem boundaries.

## Platform Layers

- Frontend: React/Vite enterprise dashboard with scan, reports, platform, coverage, plugins, and CI/CD workspaces.
- API Gateway: FastAPI route layer with health, scan orchestration, reports, lifecycle, tenancy, platform, queue, worker, and monitoring endpoints.
- Queue and Workers: Redis/Celery-ready topology metadata with queue lanes for recon, crawl, detect, validate, and report execution.
- Persistence: SQLite local mode with PostgreSQL-ready Docker Compose and database URL configuration.
- Object Storage: local filesystem evidence/report store with S3-compatible upgrade path.
- Telemetry: websocket scan updates, timeline events, detector timings, and platform metrics.
- AI Risk Engine: deterministic exploitability prediction, deduplication clusters, prioritization, remediation brief hooks, and attack-chain hypotheses.

## Security Boundaries

Advanced vulnerability families are implemented as modular safe detectors. They identify validation candidates for NoSQL injection, command injection, LDAP/XPath, SSTI, XXE, DOM XSS, stored/blind XSS, JWT/OAuth/session/MFA, IDOR/RBAC, SSRF, upload bypasses, traversal, cache poisoning, host header attacks, WebSocket/GraphQL transport, race conditions, desync/request smuggling, prototype pollution, and DOM clobbering.

These detectors intentionally do not perform destructive exploitation. Active validation remains bounded by scan profiles, authorization confirmation, rate limits, safe replay plans, and domain allowlists.

## Recon Intelligence

Recon now enriches scans with:

- A/AAAA, MX, NS, TXT records
- PTR and RDAP/ASN enrichment when available
- TLS and WAF summaries
- robots.txt and sitemap intelligence
- favicon SHA-256 fingerprinting
- source-map candidate analysis
- cloud storage candidates
- endpoint risk ranking
- historical endpoint drift tracking

## Enterprise Outputs

Each completed scan can include:

- attack surface inventory
- API security summary
- validation summary and replay cache keys
- compliance mapping for OWASP, PCI DSS, ISO 27001, and NIST
- telemetry summary
- AI risk summary
- HTML report
- PDF report
- JSON evidence bundle

## Operations

CI templates are available for GitHub Actions, Jenkins, GitLab CI, and Azure DevOps. Docker Compose includes Redis, Postgres, API, worker, and Juice Shop services on the `adaptivescan-net` network.

The local validation baseline is:

```powershell
.\.venv\Scripts\python.exe -m pytest
cd frontend
npm run build
```
