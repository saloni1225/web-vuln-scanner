import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.app import app
from backend.config.settings import settings

client = TestClient(app)


def test_websocket_requires_authentication():
    """Verify that WebSocket connection is rejected if token is missing or invalid."""
    # 1. Missing token
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/ws/scans"):
            pass

    # 2. Invalid token
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/ws/scans?token=invalid-token"):
            pass


def test_websocket_origin_check():
    """Verify that WebSocket connection is rejected if the Origin header is not in CORS allowlist."""
    from backend.auth.saas_auth import issue_tokens
    tokens = issue_tokens("owner@test.com", role="owner", organization_id="test-org", mfa_verified=True)
    token = tokens["access_token"]

    # A blocked origin must fail upgrade handshake checks.
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            f"/api/ws/scans?token={token}",
            headers={"Origin": "https://malicious-site.com"}
        ):
            pass


def test_websocket_requires_mfa_for_admin_owner():
    """Verify that WebSocket connection is rejected for owners/admins if MFA is not verified."""
    from backend.auth.saas_auth import issue_tokens
    tokens = issue_tokens("owner@test.com", role="owner", organization_id="test-org", mfa_verified=False)
    token = tokens["access_token"]

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/api/ws/scans?token={token}"):
            pass


def test_websocket_authorization_failure():
    """Verify that WebSocket connection is rejected if the token has an unauthorized role."""
    from backend.auth.saas_auth import issue_tokens
    # Issue token for a role with no permissions (e.g. guest)
    tokens = issue_tokens("guest@test.com", role="guest", organization_id="test-org")
    token = tokens["access_token"]

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/api/ws/scans?token={token}"):
            pass


def test_websocket_missing_role_rejection():
    """Verify that WebSocket connection is rejected if the token payload is missing role claims."""
    from backend.auth.saas_auth import _encode_jwt
    import time

    now = int(time.time())
    payload = {
        "sub": "norole@test.com",
        "organization_id": "test-org",
        "iat": now,
        "exp": now + 900,
    }
    token = _encode_jwt(payload)

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/api/ws/scans?token={token}"):
            pass


def test_websocket_tenancy_isolation():
    """Verify that WebSocket connection is rejected if trying to access a scan in another org."""
    from backend.database.db import save_scan
    from backend.auth.saas_auth import issue_tokens

    # Create a mock scan for 'other-org'
    scan_id = "test-scan-tenant-iso"
    scan_data = {
        "scan_id": scan_id,
        "target_url": "http://example.com",
        "started_at": "2026-06-10T12:00:00Z",
        "finished_at": "2026-06-10T12:10:00Z",
        "findings": [],
        "organization_id": "other-org",
    }
    save_scan(scan_data)

    # Issue token for 'test-org'
    tokens = issue_tokens("engineer@test.com", role="security_engineer", organization_id="test-org")
    token = tokens["access_token"]

    # Try connecting to the scan progress WebSocket channel
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/api/ws/scans/{scan_id}?token={token}"):
            pass


@pytest.mark.anyio
async def test_startup_validation_rejects_weak_secret():
    """Verify that startup fails in non-dev execution modes if JWT secret is weak/fallback."""
    # Save original settings
    orig_secret = settings.adaptivescan_jwt_secret
    orig_mode = settings.execution_mode

    # Simulate production mode with weak secret
    settings.adaptivescan_jwt_secret = "weak"
    settings.execution_mode = "production"

    try:
        from backend.app import lifespan
        from fastapi import FastAPI
        test_app = FastAPI(lifespan=lifespan)
        with pytest.raises(RuntimeError) as exc:
            async with lifespan(test_app):
                pass
        assert "ADAPTIVESCAN_JWT_SECRET is missing, weak, or set to the fallback" in str(exc.value)
    finally:
        # Restore settings
        settings.adaptivescan_jwt_secret = orig_secret
        settings.execution_mode = orig_mode


def test_database_url_postgresql_path():
    """Verify that database path supports both sqlite and postgresql configuration patterns."""
    orig_db = settings.database_url
    try:
        # 1. PostgreSQL config
        settings.database_url = "postgresql://user:pass@localhost/db"
        from backend.database.migrations import database_backend_status
        status = database_backend_status()
        assert status["engine"] == "postgresql"
        assert status["mode"] == "enterprise"

        # 2. SQLite config
        settings.database_url = "sqlite:///test.db"
        status = database_backend_status()
        assert status["engine"] == "sqlite"
        assert status["mode"] == "local-dev"
    finally:
        settings.database_url = orig_db
