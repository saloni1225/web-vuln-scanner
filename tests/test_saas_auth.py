from fastapi.testclient import TestClient
from uuid import uuid4

from backend.app import app
from backend.auth.saas_auth import _otp_hash, issue_tokens
from backend.database.db import store_otp_challenge
from backend.config.settings import settings


client = TestClient(app)


def test_auth_architecture_exposes_enterprise_controls():
    response = client.get("/api/auth/architecture")

    assert response.status_code == 200
    body = response.json()
    assert "registration" in body["flows"]
    assert "google" in body["providers"]
    assert "rbac" in body
    assert any(control.startswith("JWT") for control in body["security_controls"])


def test_register_login_and_otp_flow(monkeypatch):
    # Enforce production mode to verify safety
    monkeypatch.setattr(settings, "execution_mode", "production")

    # Mock deliver_otp to succeed in production mode
    from backend.auth.otp_delivery import OtpDeliveryResult
    monkeypatch.setattr(
        "backend.auth.saas_auth.deliver_otp",
        lambda **kwargs: OtpDeliveryResult(provider="mock", delivered=True, destination="mock@example.com", dev_visible=False)
    )

    email = f"ada-{uuid4().hex[:8]}@example.com"
    payload = {
        "first_name": "Ada",
        "last_name": "Lovelace",
        "company_name": "Example Security",
        "work_email": email,
        "password": "CorrectHorse42!",
        "confirm_password": "CorrectHorse42!",
    }
    register_response = client.post("/api/auth/register", json=payload)

    assert register_response.status_code == 200
    registered = register_response.json()
    assert registered["user"]["role"] == "owner"
    assert registered["next_step"] == "verify-email"
    assert registered["verification"]["delivery"] == "email"
    # SECURITY: dev_code must NOT be in the OTP response in production
    assert "dev_code" not in registered["verification"]

    # Restore to test mode
    monkeypatch.setattr(settings, "execution_mode", "test")

    bad_login_response = client.post("/api/auth/login", json={"email": email, "password": "wrong-password"})
    assert bad_login_response.status_code == 200
    assert bad_login_response.json()["authenticated"] is False

    login_response = client.post("/api/auth/login", json={"email": email, "password": "CorrectHorse42!"})
    assert login_response.status_code == 200
    login = login_response.json()
    # SECURITY FIX: MFA users must NOT receive tokens before completing OTP.
    # authenticated should be False (pending MFA), requires_mfa should be True.
    assert login["requires_mfa"] is True
    assert login["authenticated"] is False, (
        "SECURITY BUG: tokens were issued before MFA was verified!"
    )
    assert "tokens" not in login, (
        "SECURITY BUG: tokens must not be present in login response when MFA is required!"
    )
    assert "pending_mfa_email" in login
    assert "mfa" in login

    wrong_otp_response = client.post("/api/auth/otp/verify", json={"email": email, "code": "123456", "purpose": "login_mfa"})
    assert wrong_otp_response.status_code == 200
    assert wrong_otp_response.json()["verified"] is False

    # Note: In production, the OTP code is sent via email/TOTP app.
    # In tests, we'd need to query the DB or mock the OTP store.
    # We test that wrong codes are rejected correctly.


def test_auth_bootstrap_after_mfa_and_logout_clears_session():
    local_client = TestClient(app)
    email = f"mfa-{uuid4().hex[:8]}@example.com"
    password = "CorrectHorse42!"
    payload = {
        "first_name": "Mfa",
        "last_name": "User",
        "company_name": "Example Security",
        "work_email": email,
        "password": password,
        "confirm_password": password,
    }
    assert local_client.post("/api/auth/register", json=payload).status_code == 200
    login_response = local_client.post("/api/auth/login", json={"email": email, "password": password})
    assert login_response.status_code == 200
    assert login_response.json()["requires_mfa"] is True
    assert local_client.get("/api/auth/me").status_code == 401

    code = "654321"
    store_otp_challenge(
        email=email,
        purpose="login_mfa",
        code_hash=_otp_hash(email, "login_mfa", code),
        expires_at=4_102_444_800,
    )
    mfa_response = local_client.post("/api/auth/otp/verify", json={"email": email, "code": code, "purpose": "login_mfa"})
    assert mfa_response.status_code == 200
    assert mfa_response.json()["authenticated"] is True
    assert mfa_response.json()["tokens"]["access_token"].count(".") == 2

    me = local_client.get("/api/auth/me")
    assert me.status_code == 200
    body = me.json()
    assert body["authenticated"] is True
    assert body["email"] == email
    assert body["role"] == "owner"
    assert body["mfaVerified"] is True
    assert "org:admin" in body["permissions"]

    logout = local_client.post("/api/auth/logout", json={"email": email})
    assert logout.status_code == 200
    assert logout.json()["logged_out"] is True
    assert local_client.get("/api/auth/me").status_code == 401


def test_auth_distinguishes_401_and_403_for_protected_routes():
    unauthenticated = client.get("/api/team")
    assert unauthenticated.status_code == 401

    viewer_tokens = issue_tokens("viewer@example.com", role="viewer", organization_id="org-test", mfa_verified=True)
    viewer_headers = {"Authorization": f"Bearer {viewer_tokens['access_token']}"}
    forbidden = client.get("/api/team", headers=viewer_headers)
    assert forbidden.status_code == 403
    assert forbidden.json()["detail"]["required_permission"] == "rbac:admin"

    owner_tokens = issue_tokens("owner@example.com", role="owner", organization_id="org-test", mfa_verified=True)
    owner_headers = {"Authorization": f"Bearer {owner_tokens['access_token']}"}
    allowed = client.get("/api/team", headers=owner_headers)
    assert allowed.status_code == 200


def test_websocket_blocks_unauthenticated_connections():
    local_client = TestClient(app)
    try:
        with local_client.websocket_connect("/api/ws/scans"):
            raise AssertionError("Unauthenticated websocket should not connect")
    except Exception as exc:
        assert "1008" in str(exc) or "WebSocketDisconnect" in exc.__class__.__name__



def test_onboarding_and_billing_foundation():
    # Create a valid auth token for an admin user to test authenticated routes
    tokens = issue_tokens("admin@test.com", role="owner", organization_id="test-org", mfa_verified=True)
    access_token = tokens["access_token"]
    auth_headers = {"Authorization": f"Bearer {access_token}"}

    onboarding = client.get("/api/onboarding")  # Public route
    billing = client.get("/api/billing/catalog", headers=auth_headers)
    subscription = client.get("/api/billing/subscription", headers=auth_headers)
    team = client.get("/api/team", headers=auth_headers)
    notifications = client.get("/api/notifications", headers=auth_headers)
    workflows = client.get("/api/monitoring/workflows", headers=auth_headers)
    trust = client.get("/api/trust")

    assert onboarding.status_code == 200
    assert [step["id"] for step in onboarding.json()["steps"]] == ["organization", "domain", "mode", "team", "notifications", "launch"]
    assert billing.status_code == 200
    assert [plan["name"] for plan in billing.json()["plans"]] == ["Starter", "Professional", "Business", "Enterprise"]
    assert subscription.status_code == 200
    assert "usage" in subscription.json()
    assert team.status_code == 200
    assert team.json()["members"]
    assert notifications.status_code == 200
    assert workflows.status_code == 200
    assert trust.status_code == 200

    assert workflows.json()["operating_model"] == ["organization", "assets", "monitoring", "exposure", "findings", "reports"]
    assert trust.status_code == 200
    assert "MFA enforcement" in trust.json()["security"]
