# Security Policy — AdaptiveScan

## Reporting a Vulnerability

If you discover a security vulnerability in AdaptiveScan, please **do not open a public GitHub issue**.

Instead, report it through one of the following channels:

- **Email**: security@adaptivescan.io *(replace with your actual contact)*
- **GitHub Private Advisory**: [Report a vulnerability](../../security/advisories/new)

We will acknowledge your report within **48 hours** and provide a resolution timeline within **7 days**.

---

## Scope

The following are **in scope** for security reports:

| Asset | Type |
|-------|------|
| `localhost` AdaptiveScan web application | Web App |
| `/api/*` REST endpoints | API |
| `/ws/*` WebSocket endpoints | API |
| Authentication & session management | Backend |
| Scan engine (SSRF, injection, path traversal) | Backend |

The following are **out of scope**:

- Third-party services and libraries (report to their maintainers)
- Findings with no practical security impact
- Rate limiting bypasses that require more than 10,000 requests/minute
- Self-XSS (requires the attacker to run code in their own browser)
- Social engineering attacks

---

## Bug Bounty Readiness Checklist

Before making this repository public or submitting to a bug bounty program:

### 🔴 Critical (Must Fix)
- [ ] Set `ADAPTIVESCAN_JWT_SECRET` to a 64-char random hex secret in production
- [ ] Ensure `.env` is never committed (check with `git log --all -- .env`)
- [ ] Rotate any secrets that were ever committed to Git history
- [ ] Move from `localStorage` token storage to httpOnly cookies (done in v1.1)
- [ ] Enable `COOKIE_SECURE=true` and `ADAPTIVESCAN_HSTS=true` when behind HTTPS

### 🟡 High (Fix Before Public Repo)
- [ ] Set `ADAPTIVESCAN_EXPOSE_DOCS=false` in production
- [ ] Add TOTP-based MFA (not just email OTP)
- [ ] Implement refresh token rotation (invalidate old on reuse)
- [ ] Add account enumeration protection (timing-safe email lookup)
- [ ] Verify all API endpoints require authentication (audit `/api/*` routes)

### 🟢 Medium (Harden Further)
- [ ] Add Content-Security-Policy report-uri directive
- [ ] Implement proper server-side session invalidation on logout
- [ ] Add request signing for webhook deliveries
- [ ] Enable SQLite WAL mode and connection pooling
- [ ] Set `max_age` on all cookies appropriately

---

## Security Architecture

```
Browser ──── HTTPS/TLS ──── Reverse Proxy (Caddy/Nginx)
                                    │
                                    ▼
                        FastAPI (backend/app.py)
                         │
                 ┌───────┼────────┐
                 ▼       ▼        ▼
         Rate    CSRF   JWT     Security
         Limit   Guard  Guard   Headers
                 │
                 ▼
          SQLite / scanner.db
```

**Authentication flow**: Register → Email OTP verify → Login → MFA challenge → JWT issued in httpOnly cookie

**SSRF protection**: All scan targets validated against RFC1918 + loopback blocklists before any network I/O

**Rate limiting**: Sliding-window per-IP on all endpoints; progressive lockout after 5 failed auth attempts within 5 minutes (15-minute lockout)

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (`main`) | ✅ Yes |
| Older branches | ❌ No |

---

*© 2025 Recoxy / AdaptiveScan. All rights reserved.*
