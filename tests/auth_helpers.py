"""
Test authentication helpers
============================
Provides a pre-authenticated test client and JWT token generator
for tests that need to call protected API routes.
"""
import base64
import hashlib
import hmac
import json
import time

from fastapi.testclient import TestClient

from backend.app import app
from backend.security.jwt_guard import JWT_SECRET


def _make_test_jwt(
    sub: str = "test-admin@adaptivescan.local",
    role: str = "owner",
    ttl: int = 3600,
) -> str:
    """Generate a valid HS256 JWT for testing."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": sub,
        "role": role,
        "organization_id": "test-org",
        "exp": int(time.time()) + ttl,
    }
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = base64.urlsafe_b64encode(
        hmac.new(JWT_SECRET, signing_input, hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return f"{h_b64}.{p_b64}.{sig}"


def authenticated_client(role: str = "owner") -> TestClient:
    """Return a TestClient with a valid JWT in the Authorization header."""
    token = _make_test_jwt(role=role)
    client = TestClient(app)
    client.headers["Authorization"] = f"Bearer {token}"
    return client


# Pre-built clients for common test scenarios
admin_client = authenticated_client("owner")
viewer_client = authenticated_client("viewer")
