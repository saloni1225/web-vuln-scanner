import pytest
from fastapi.testclient import TestClient
from backend.app import app
from backend.config.settings import settings
from backend.auth.saas_auth import get_auth_user_by_email, seed_founder_user
from backend.database.db import get_connection

client = TestClient(app)

def test_founder_seeding_and_login_flow(monkeypatch):
    # 1. Verify environment gating (does not seed in production)
    monkeypatch.setattr(settings, "execution_mode", "production")
    monkeypatch.setattr(settings, "enable_founder_seed", True)
    monkeypatch.setattr(settings, "founder_email", "prod_founder@test.com")
    monkeypatch.setattr(settings, "founder_password", "ProdTest@1234")
    
    seed_founder_user()
    assert get_auth_user_by_email("prod_founder@test.com") is None

    # 2. Verify environment gating (does not seed if enable_founder_seed is False)
    monkeypatch.setattr(settings, "execution_mode", "local-dev")
    monkeypatch.setattr(settings, "enable_founder_seed", False)
    monkeypatch.setattr(settings, "founder_email", "disabled_founder@test.com")
    monkeypatch.setattr(settings, "founder_password", "Test@1234")
    
    seed_founder_user()
    assert get_auth_user_by_email("disabled_founder@test.com") is None

    # 3. Seed founder user in non-production
    monkeypatch.setattr(settings, "execution_mode", "local-dev")
    monkeypatch.setattr(settings, "enable_founder_seed", True)
    monkeypatch.setattr(settings, "founder_email", "founder@test.com")
    monkeypatch.setattr(settings, "founder_password", "Founder@1234")
    
    # Run seeding
    seed_founder_user()
    user = get_auth_user_by_email("founder@test.com")
    assert user is not None
    assert user["role"] == "owner"
    
    # Run seeding again to test idempotency (should not crash or create duplicates)
    seed_founder_user()
    
    # 4. Verify login flow (bypasses MFA entirely)
    login_payload = {
        "email": "founder@test.com",
        "password": "Founder@1234"
    }
    response = client.post("/api/auth/login", json=login_payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["authenticated"] is True
    assert res_data["requires_mfa"] is False
    assert "tokens" in res_data
    assert res_data["tokens"]["access_token"] is not None

    # 5. Access a protected endpoint using the token
    token = res_data["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Access a protected route (e.g. /api/auth/me)
    me_response = client.get("/api/auth/me", headers=headers)
    assert me_response.status_code == 200
    me_data = me_response.json()
    assert me_data["email"] == "founder@test.com"
    assert me_data["role"] == "owner"
    assert me_data["mfaVerified"] is True

    # 6. Test WebSocket principal resolution for founder user
    try:
        with client.websocket_connect(f"/api/ws/scans?token={token}"):
            pass
    except Exception as exc:
        pytest.fail(f"WebSocket connection failed for founder user: {exc}")
