# AdaptiveScan Auth Flow

AdaptiveScan uses a SaaS identity model built around organizations, workspace access, RBAC, MFA, JWT access tokens, refresh sessions, and audit logs.

## Registration

1. User submits first name, last name, company name, work email, password, and confirmation.
2. Backend validates work email and password policy.
3. Organization is created on the starter trial plan.
4. Production workspace is created.
5. Owner user is created with a PBKDF2 password hash.
6. Email verification OTP is issued.
7. Audit log records registration and OTP issuance.
8. Frontend routes user to OTP verification, then onboarding.

## Login

1. User submits work email and password.
2. Backend validates password hash.
3. Login success writes an audit event.
4. Access and refresh tokens are issued.
5. MFA challenge is issued when required.
6. Frontend routes user to MFA verification.
7. Successful MFA routes to the enterprise dashboard.

## OTP And MFA

OTP challenges are scoped by:

- `email`
- `purpose`
- `code_hash`
- `expires_at`

Supported purposes:

- `email_verification`
- `login_mfa`
- `password_reset`
- `passwordless_login`

## Token Strategy

- Access token: JWT, short lived.
- Refresh token: JWT-style token with stored hash for session tracking.
- Token payload includes subject, role, organization ID, issue time, and expiry.

## RBAC

Roles map to product permissions such as:

- exposure read
- attack graph read
- attack path read
- drift read
- telemetry read
- orchestration read
- AI intelligence read

The backend uses permission dependencies for sensitive operational routes.

## Enterprise Identity Roadmap

Identity provider abstraction should support:

- Google SSO
- GitHub SSO
- Microsoft SSO
- OIDC
- SAML
- SCIM

## Security Controls

- MFA enforcement
- PBKDF2 password hashing
- JWT access tokens
- Refresh-session storage
- OTP expiration and single-use consumption
- API key management
- Tenant isolation through organization and workspace IDs
- Audit logging for auth events
- Rate-limit-ready API boundary
