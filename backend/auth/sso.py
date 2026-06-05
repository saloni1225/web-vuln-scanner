from __future__ import annotations


def identity_provider_catalog() -> dict[str, object]:
    return {
        "providers": [
            {"id": "google", "name": "Google Workspace", "protocol": "OIDC", "status": "ready"},
            {"id": "github", "name": "GitHub", "protocol": "OAuth2/OIDC", "status": "ready"},
            {"id": "microsoft", "name": "Microsoft Entra ID", "protocol": "OIDC", "status": "ready"},
            {"id": "oidc", "name": "Custom OIDC", "protocol": "OIDC", "status": "configurable"},
            {"id": "saml", "name": "Enterprise SAML", "protocol": "SAML 2.0", "status": "configurable"},
        ],
        "scim": {"status": "planned", "features": ["user provisioning", "group sync", "deactivation sync"]},
        "configuration_fields": ["issuer", "client_id", "client_secret_ref", "redirect_uri", "allowed_domains", "default_role"],
    }


def sso_configuration(org_id: str = "local-org") -> dict[str, object]:
    return {
        "organization_id": org_id,
        "enabled": False,
        "default_provider": "",
        "enforcement": "optional",
        "jit_provisioning": True,
        "domain_allowlist": [],
        "providers": identity_provider_catalog()["providers"],
    }
