from fastapi.testclient import TestClient
from uuid import uuid4

from backend.app import app


client = TestClient(app)


def test_auth_architecture_exposes_enterprise_controls():
    response = client.get("/api/auth/architecture")

    assert response.status_code == 200
    body = response.json()
    assert "registration" in body["flows"]
    assert "google" in body["providers"]
    assert "rbac" in body
    assert any(control.startswith("JWT") for control in body["security_controls"])


def test_register_login_and_otp_flow():
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
    # SECURITY: dev_code must NOT be in the OTP response
    assert "dev_code" not in registered["verification"]

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



def test_onboarding_and_billing_foundation():
    from backend.auth.saas_auth import issue_tokens
    # Create a valid auth token for an admin user to test authenticated routes
    tokens = issue_tokens("admin@test.com", role="owner", organization_id="test-org")
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
