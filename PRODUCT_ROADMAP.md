# AdaptiveScan Product Roadmap

AdaptiveScan is becoming a commercial ASM, exposure intelligence, monitoring, reporting, billing, authentication, AI copilot, enterprise integrations, and multi-tenant SaaS platform.

## Phase 1: Commercial SaaS Foundation

- Public website
- Features, pricing, documentation, contact, trust, login, and register pages
- SaaS onboarding
- Organization and workspace foundation
- RBAC, MFA, OTP, JWT-ready auth
- Billing catalog and subscription architecture
- Team management
- Notification center
- Activity center

## Phase 2: ASM And Exposure Operations

- Continuous asset discovery
- Domains, subdomains, APIs, GraphQL, services, certificates, technologies, WAF/CDN, cloud assets, public buckets, and internet-facing services
- Asset relationships, ownership, tagging, history, and exposure timeline
- Asset graph: domain -> APIs -> services -> certificates -> findings

## Phase 3: Recon And API Intelligence

- JavaScript endpoint extraction
- Source map discovery
- Secret and JWT discovery
- Admin route discovery
- OpenAPI, Swagger, GraphQL, and undocumented API discovery
- Schema analysis
- Session, OAuth, role, and auth boundary intelligence

## Phase 4: Attack Path Correlation

- Attack graph engine
- Correlate exposed APIs, weak auth, IDOR, sensitive assets, and cloud exposure
- Generate attack chains, trust relationships, and identity relationships
- Prioritize critical attack paths

## Phase 5: AI Security Copilot

- Risk prioritization
- Finding deduplication
- Exploitability prediction
- Attack path explanations
- Executive summaries
- Remediation suggestions
- Exposure explanations
- Hugging Face, local model, and provider abstraction support

## Phase 6: Enterprise Integrations

- Slack, Microsoft Teams, Discord, Jira, GitHub, GitLab, ServiceNow, Splunk, Elastic, and Microsoft Sentinel
- Webhooks
- Alert forwarding
- Ticket creation
- Marketplace architecture

## Phase 7: Enterprise Identity And Security

- Google SSO, GitHub SSO, Microsoft SSO
- OIDC, SAML, SCIM
- CSP, CSRF protection, rate limiting, secrets management
- Tenant isolation
- Encryption at rest and in transit
- OWASP ASVS alignment

## Phase 8: Public API And Founder Analytics

- Assets API
- Findings API
- Reports API
- Monitoring API
- Notifications API
- API documentation portal
- Founder dashboard for MRR, ARR, trials, conversions, active organizations, monitored assets, scan volume, and retention

## Success Metrics

- Time to first monitored asset
- Trial activation rate
- Trial to paid conversion
- Monitored assets per organization
- Alert action rate
- Report export rate
- Retention by integration usage
