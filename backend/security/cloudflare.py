import os
import logging
from fastapi import Request

logger = logging.getLogger(__name__)

# Configurable Cloudflare settings
CLOUDFLARE_ACCESS_ENABLED = os.environ.get("CLOUDFLARE_ACCESS_ENABLED", "false").lower() == "true"
CLOUDFLARE_ACCESS_AUD = os.environ.get("CLOUDFLARE_ACCESS_AUD", "")
CLOUDFLARE_ACCESS_TEAM = os.environ.get("CLOUDFLARE_ACCESS_TEAM", "")

def verify_cloudflare_assertion(request: Request) -> str | None:
    """
    Verifies the Cloudflare Access JWT assertion header.
    Returns the authenticated user's email if valid, or None if invalid/missing.
    """
    if not CLOUDFLARE_ACCESS_ENABLED:
        return None

    assertion = request.headers.get("cf-access-jwt-assertion")
    if not assertion:
        return None

    try:
        import jwt
        # PyJWT JWK client to fetch and cache certificates from Cloudflare JWKS endpoint
        jwks_url = f"https://{CLOUDFLARE_ACCESS_TEAM}.cloudflareaccess.com/cdn-cgi/access/certs"
        jwks_client = jwt.PyJWKClient(jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(assertion)
        
        payload = jwt.decode(
            assertion,
            signing_key.key,
            algorithms=["RS256"],
            audience=CLOUDFLARE_ACCESS_AUD,
            issuer=f"https://{CLOUDFLARE_ACCESS_TEAM}.cloudflareaccess.com"
        )
        return payload.get("email")
    except Exception as exc:
        logger.error(f"Cloudflare Access JWT assertion validation failed: {exc}")
        return None
