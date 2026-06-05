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
        "password": "CorrectHorse42",
        "confirm_password": "CorrectHorse42",
    }
    register_response = client.post("/api/auth/register", json=payload)

    assert register_response.status_code == 200
    registered = register_response.json()
    assert registered["user"]["role"] == "owner"
    assert registered["next_step"] == "verify-email"
    assert registered["verification"]["delivery"] == "email"

    bad_login_response = client.post("/api/auth/login", json={"email": email, "password": "wrong-password"})
    assert bad_login_response.status_code == 200
    assert bad_login_response.json()["authenticated"] is False

    login_response = client.post("/api/auth/login", json={"email": email, "password": "CorrectHorse42"})
    assert login_response.status_code == 200
    login = login_response.json()
    assert login["authenticated"] is True
    assert login["requires_mfa"] is True
    assert login["tokens"]["access_token"].count(".") == 2

    wrong_otp_response = client.post("/api/auth/otp/verify", json={"email": email, "code": "123456", "purpose": "login_mfa"})
    assert wrong_otp_response.status_code == 200
    assert wrong_otp_response.json()["verified"] is False

    otp_response = client.post("/api/auth/otp/verify", json={"email": email, "code": login["mfa"]["challenge"]["dev_code"], "purpose": "login_mfa"})
    assert otp_response.status_code == 200
    assert otp_response.json()["verified"] is True


def test_onboarding_and_billing_foundation():
    onboarding = client.get("/api/onboarding")
    billing = client.get("/api/billing/catalog")
    subscription = client.get("/api/billing/subscription")
    team = client.get("/api/team")
    notifications = client.get("/api/notifications")
    workflows = client.get("/api/monitoring/workflows")
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
    assert notifications.json()["rules"]
    assert workflows.status_code == 200
    assert workflows.json()["operating_model"] == ["organization", "assets", "monitoring", "exposure", "findings", "reports"]
    assert trust.status_code == 200
    assert "MFA enforcement" in trust.json()["security"]
