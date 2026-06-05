# SSO Report

AdaptiveScan includes an enterprise identity provider abstraction layer.

## Implemented

- `/api/sso/providers`
- `/api/sso/configuration`
- SSO provider catalog module
- Configuration model for issuer, client ID, secret reference, redirect URI, domains, and default role

## Supported Providers

- Google Workspace
- GitHub
- Microsoft Entra ID
- Custom OIDC
- Enterprise SAML

## Roadmap

- SCIM user provisioning
- Group synchronization
- SSO enforcement by domain
- JIT provisioning with role mapping
