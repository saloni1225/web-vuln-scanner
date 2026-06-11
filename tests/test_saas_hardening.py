import pytest
import pyotp
import secrets
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from uuid import uuid4

from backend.app import app, lifespan
from backend.config.settings import settings
from backend.database.db import get_auth_user_by_email, update_user_mfa, get_connection
from backend.rbac.auth import Principal, current_principal
from backend.security.jwt_guard import ACCESS_COOKIE, REFRESH_COOKIE

client = TestClient(app)


def test_csrf_enforcement_blocks_state_changing_methods():
    email = f"csrf-{uuid4().hex[:8]}@example.com"
    # Create user with MFA disabled so we can log in directly and get tokens
    update_user_mfa(email, "", "", mfa_enabled=False)
    
    # 1. Try a POST request without logging in. It should fail with 401 (not authenticated)
    response = client.post("/api/auth/mfa/enroll")
    assert response.status_code == 401

    # Let's register the user properly first
    register_payload = {
        "first_name": "CSRF",
        "last_name": "Test",
        "company_name": "CSRF Corp",
        "work_email": email,
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
    }
    register_response = client.post("/api/auth/register", json=register_payload)
    assert register_response.status_code == 200
    
    # Update to disable MFA in db so we can log in directly, and change role to analyst to bypass owner/admin MFA block
    update_user_mfa(email, "", "", mfa_enabled=False)
    with get_connection() as conn:
        conn.execute("UPDATE auth_users SET role = 'analyst' WHERE email = ?", (email,))

    # 2. Log in to get auth cookies
    login_response = client.post("/api/auth/login", json={"email": email, "password": "SecurePassword123!"})
    assert login_response.status_code == 200
    
    # Extract access cookie
    access_cookie = login_response.cookies.get(ACCESS_COOKIE)
    csrf_cookie = login_response.cookies.get("adaptivescan_csrf")
    
    assert access_cookie is not None
    assert csrf_cookie is not None

    # 3. Call a state-changing route (POST) without the X-CSRF-Token header. It should fail with 403
    headers = {"Origin": "http://localhost:5173"} # Set Origin to trigger CSRF validation
    response = client.post(
        "/api/auth/mfa/enroll",
        headers=headers,
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "csrf_missing_header"

    # 4. Call with mismatching header. It should fail with 403
    headers = {
        "Origin": "http://localhost:5173",
        "X-CSRF-Token": "invalid-token-value"
    }
    response = client.post(
        "/api/auth/mfa/enroll",
        headers=headers,
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "csrf_token_mismatch"

    # 5. Call with matching header. It should pass the CSRF check and succeed
    headers = {
        "Origin": "http://localhost:5173",
        "X-CSRF-Token": csrf_cookie
    }
    response = client.post(
        "/api/auth/mfa/enroll",
        headers=headers,
    )
    assert response.status_code == 200


def test_cookie_security_flags_in_production(monkeypatch):
    # Set to production mode
    monkeypatch.setattr(settings, "execution_mode", "production")
    monkeypatch.setattr(settings, "adaptivescan_jwt_secret", "secure-production-jwt-secret-at-least-32-chars")
    
    # Mock deliver_otp to succeed in production mode
    from backend.auth.otp_delivery import OtpDeliveryResult
    monkeypatch.setattr(
        "backend.auth.saas_auth.deliver_otp",
        lambda **kwargs: OtpDeliveryResult(provider="mock", delivered=True, destination="mock@example.com", dev_visible=False)
    )
    
    email = f"cookie-{uuid4().hex[:8]}@example.com"
    register_payload = {
        "first_name": "Cookie",
        "last_name": "Test",
        "company_name": "Cookie Corp",
        "work_email": email,
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
    }
    client.post("/api/auth/register", json=register_payload)
    update_user_mfa(email, "", "", mfa_enabled=False)

    login_response = client.post("/api/auth/login", json={"email": email, "password": "SecurePassword123!"})
    assert login_response.status_code == 200
    
    # Check headers for cookies
    cookies_headers = login_response.headers.get_list("set-cookie")
    assert len(cookies_headers) > 0
    
    # Verify that the access cookie is Secure, HttpOnly, and SameSite=Strict
    access_cookie_header = [h for h in cookies_headers if ACCESS_COOKIE in h][0]
    assert "Secure" in access_cookie_header
    assert "HttpOnly" in access_cookie_header or "httponly" in access_cookie_header.lower()
    assert "SameSite=Strict" in access_cookie_header


@pytest.mark.anyio
async def test_lifespan_validation_fails_closed_in_production(monkeypatch):
    # 1. Test exposed docs in production raises RuntimeError
    monkeypatch.setattr(settings, "execution_mode", "production")
    monkeypatch.setattr(settings, "adaptivescan_expose_docs", True)
    monkeypatch.setattr(settings, "adaptivescan_jwt_secret", "secure-production-jwt-secret-at-least-32-chars")

    test_app = FastAPI(lifespan=lifespan)
    with pytest.raises(RuntimeError) as exc:
        async with lifespan(test_app):
            pass
    assert "Docs cannot be exposed" in str(exc.value)

    # 2. Test insecure JWT secret in production raises RuntimeError
    monkeypatch.setattr(settings, "execution_mode", "production")
    monkeypatch.setattr(settings, "adaptivescan_expose_docs", False)
    monkeypatch.setattr(settings, "adaptivescan_jwt_secret", "adaptivescan-local-development-secret")

    with pytest.raises(RuntimeError) as exc:
        async with lifespan(test_app):
            pass
    assert "ADAPTIVESCAN_JWT_SECRET is missing, weak, or set to the fallback" in str(exc.value)


def test_totp_mfa_enrollment_verification_and_login():
    email = f"mfa-{uuid4().hex[:8]}@example.com"
    register_payload = {
        "first_name": "MFA",
        "last_name": "Test",
        "company_name": "MFA Corp",
        "work_email": email,
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
    }
    client.post("/api/auth/register", json=register_payload)
    # Start with MFA disabled so we can log in and enroll
    update_user_mfa(email, "", "", mfa_enabled=False)

    # Log in
    login_res = client.post("/api/auth/login", json={"email": email, "password": "SecurePassword123!"})
    assert login_res.status_code == 200
    
    # Call enroll
    enroll_res = client.post("/api/auth/mfa/enroll")
    assert enroll_res.status_code == 200
    enroll_data = enroll_res.json()
    assert "totp_secret" in enroll_data
    assert "provisioning_uri" in enroll_data
    
    secret = enroll_data["totp_secret"]
    
    # Call verify with a wrong code
    verify_res = client.post("/api/auth/mfa/verify", json={"code": "123456"})
    assert verify_res.status_code == 400
    
    # Call verify with the correct code
    totp = pyotp.TOTP(secret)
    correct_code = totp.now()
    verify_res = client.post("/api/auth/mfa/verify", json={"code": correct_code})
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["verified"] is True
    assert "recovery_codes" in verify_data
    assert len(verify_data["recovery_codes"]) == 8
    
    recovery_codes = verify_data["recovery_codes"]

    # Log out
    client.post("/api/auth/logout", json={"email": email})
    
    # Log in again. It should require MFA now!
    login_res = client.post("/api/auth/login", json={"email": email, "password": "SecurePassword123!"})
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["requires_mfa"] is True
    assert login_data["mfa"]["methods"] == ["totp", "backup_code"]
    
    # Call verify-login with wrong code
    login_verify_res = client.post("/api/auth/mfa/verify-login", json={"email": email, "code": "123456"})
    assert login_verify_res.status_code == 400

    # Call verify-login with correct code
    correct_code = totp.now()
    login_verify_res = client.post("/api/auth/mfa/verify-login", json={"email": email, "code": correct_code})
    assert login_verify_res.status_code == 200
    assert login_verify_res.json()["authenticated"] is True
    assert "tokens" in login_verify_res.json()
    
    # Log out
    client.post("/api/auth/logout", json={"email": email})

    # Log in again and test recovery code login
    login_res = client.post("/api/auth/login", json={"email": email, "password": "SecurePassword123!"})
    assert login_res.status_code == 200
    
    # Use first recovery code
    recovery_code = recovery_codes[0]
    login_verify_res = client.post("/api/auth/mfa/verify-login", json={"email": email, "code": recovery_code})
    assert login_verify_res.status_code == 200
    assert login_verify_res.json()["authenticated"] is True

    # Try to reuse the same recovery code. It should be consumed and fail!
    client.post("/api/auth/logout", json={"email": email})
    login_res = client.post("/api/auth/login", json={"email": email, "password": "SecurePassword123!"})
    assert login_res.status_code == 200
    
    login_verify_res = client.post("/api/auth/mfa/verify-login", json={"email": email, "code": recovery_code})
    assert login_verify_res.status_code == 400


def test_admin_mfa_enforcement_prevents_administrative_actions():
    email = f"admin-mfa-{uuid4().hex[:8]}@example.com"
    register_payload = {
        "first_name": "AdminMFA",
        "last_name": "Test",
        "company_name": "AdminMFA Corp",
        "work_email": email,
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
    }
    client.post("/api/auth/register", json=register_payload)
    
    # Owner registered, MFA disabled initially
    update_user_mfa(email, "", "", mfa_enabled=False)

    # Log in to get session tokens
    login_res = client.post("/api/auth/login", json={"email": email, "password": "SecurePassword123!"})
    assert login_res.status_code == 200
    
    # 1. Try to access reports (an administrative route). It should return 403 Forbidden with detail mfa_required
    reports_res = client.get("/api/reports")
    assert reports_res.status_code == 403
    assert reports_res.json()["detail"] == "mfa_required"

    # 2. Try to access MFA enrollment (exempt). It should succeed (200)
    enroll_res = client.post("/api/auth/mfa/enroll")
    assert enroll_res.status_code == 200
    secret = enroll_res.json()["totp_secret"]

    # 3. Setup MFA
    totp = pyotp.TOTP(secret)
    client.post("/api/auth/mfa/verify", json={"code": totp.now()})

    # Now MFA is configured! Try accessing reports again. It should succeed (200)
    # Wait, we need to refresh the JWT to get a token with mfa_verified=True!
    # In real flow, the user does verify-login. Let's verify-login
    verify_login_res = client.post("/api/auth/mfa/verify-login", json={"email": email, "code": totp.now()})
    assert verify_login_res.status_code == 200

    reports_res = client.get("/api/reports")
    assert reports_res.status_code == 200


def test_audit_logging_correlation_ids():
    from backend.database.db import list_audit_logs
    email = f"audit-{uuid4().hex[:8]}@example.com"
    corr_id = f"test-corr-{uuid4().hex[:8]}"

    # Send register request with correlation ID header
    register_payload = {
        "first_name": "Audit",
        "last_name": "Test",
        "company_name": "Audit Corp",
        "work_email": email,
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
    }
    headers = {"X-Correlation-ID": corr_id}
    res = client.post("/api/auth/register", json=register_payload, headers=headers)
    assert res.status_code == 200
    
    # Check that correlation ID is returned in the response headers
    assert res.headers.get("X-Correlation-ID") == corr_id
    
    # Check that the database audit log has recorded the correlation ID
    logs = list_audit_logs(limit=10)
    # Find the log for this registration
    matching_log = [l for l in logs if l.get("event_type") == "auth.user.registered" and l.get("actor") == email]
    assert len(matching_log) == 1
    assert matching_log[0]["correlation_id"] == corr_id


def test_auth_me_endpoint():
    # 1. Unauthenticated /api/auth/me should return 401
    client.cookies.clear()
    res = client.get("/api/auth/me")
    assert res.status_code == 401

    # 2. Authenticated but MFA not verified (for analyst - MFA not forced)
    email = f"me-analyst-{uuid4().hex[:8]}@example.com"
    register_payload = {
        "first_name": "Me",
        "last_name": "Analyst",
        "company_name": "Me Corp",
        "work_email": email,
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
    }
    reg_res = client.post("/api/auth/register", json=register_payload)
    assert reg_res.status_code == 200, f"Register failed: {reg_res.text}"
    update_user_mfa(email, "", "", mfa_enabled=False)
    with get_connection() as conn:
        conn.execute("UPDATE auth_users SET role = 'analyst' WHERE email = ?", (email,))
        
    login_res = client.post("/api/auth/login", json={"email": email, "password": "SecurePassword123!"})
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    res = client.get("/api/auth/me")
    assert res.status_code == 200, f"Auth me failed: {res.text}"
    data = res.json()
    assert data["email"] == email
    assert data["role"] == "analyst"
    assert data["mfa_enabled"] is False
    assert data["session_valid"] is True


    # 3. Authenticated owner but MFA not completed (MFA forced on general routes but exempt on /api/auth/me)
    client.cookies.clear()
    email_owner = f"me-owner-{uuid4().hex[:8]}@example.com"
    register_payload = {
        "first_name": "Me",
        "last_name": "Owner",
        "company_name": "Me Corp",
        "work_email": email_owner,
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
    }
    client.post("/api/auth/register", json=register_payload)
    # Start with MFA disabled so we can log in to get session cookies, but without mfa_verified=True in JWT
    update_user_mfa(email_owner, "", "", mfa_enabled=False)
    
    # Log in initially (sets cookies, but token doesn't have mfa_verified=True yet)
    client.post("/api/auth/login", json={"email": email_owner, "password": "SecurePassword123!"})
    
    # General protected routes should be blocked
    reports_res = client.get("/api/reports")
    assert reports_res.status_code == 403
    assert reports_res.json()["detail"] == "mfa_required"
    
    # /api/auth/me should succeed because it is exempt
    me_res = client.get("/api/auth/me")
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["email"] == email_owner
    assert me_data["role"] == "owner"
    assert me_data["mfa_enabled"] is False
    assert me_data["mfa_verified"] is False



