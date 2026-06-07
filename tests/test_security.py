"""
Security module unit tests
===========================
Tests for rate limiting, SSRF guard, JWT verification, input validation, and CSRF.
"""
import pytest
from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Input Validation Tests
# ---------------------------------------------------------------------------

class TestPasswordStrength:
    def test_rejects_short_password(self):
        from backend.security.input_validation import validate_password_strength
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            validate_password_strength("Abc1!")
        assert exc_info.value.status_code == 400
        assert "12 characters" in str(exc_info.value.detail)

    def test_rejects_no_uppercase(self):
        from backend.security.input_validation import validate_password_strength
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            validate_password_strength("correct_horse42!")

    def test_rejects_no_special_char(self):
        from backend.security.input_validation import validate_password_strength
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            validate_password_strength("CorrectHorse42Abc")

    def test_accepts_strong_password(self):
        from backend.security.input_validation import validate_password_strength
        # Should not raise
        validate_password_strength("CorrectHorse42!")

    def test_rejects_common_password(self):
        from backend.security.input_validation import validate_password_strength, _COMMON_PASSWORDS
        from fastapi import HTTPException
        # Use a password that IS in the blocklist and meets length (add it temporarily)
        # "iloveyou" is in the list; pad it so length check passes first for a fairer test
        # Better: directly use a list member that's ≥12 chars or patch the list
        import backend.security.input_validation as iv
        original = iv._COMMON_PASSWORDS.copy()
        iv._COMMON_PASSWORDS.add("correcthorse42!")   # Add strong-looking but known bad
        try:
            with pytest.raises(HTTPException) as exc_info:
                validate_password_strength("CorrectHorse42!")
            assert "common" in str(exc_info.value.detail).lower()
        finally:
            iv._COMMON_PASSWORDS.clear()
            iv._COMMON_PASSWORDS.update(original)



class TestEmailValidation:
    def test_rejects_missing_at_sign(self):
        from backend.security.input_validation import validate_email
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            validate_email("notanemail")

    def test_rejects_disposable_email(self):
        from backend.security.input_validation import validate_email
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            validate_email("user@mailinator.com")
        assert "disposable" in str(exc_info.value.detail).lower()

    def test_normalises_to_lowercase(self):
        from backend.security.input_validation import validate_email
        result = validate_email("  TEST@EXAMPLE.COM  ")
        assert result == "test@example.com"

    def test_accepts_valid_email(self):
        from backend.security.input_validation import validate_email
        result = validate_email("anmol@recoxy.io")
        assert result == "anmol@recoxy.io"


class TestInjectionDetection:
    def test_detects_sql_union(self):
        from backend.security.input_validation import detect_injection
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            detect_injection("' UNION SELECT * FROM users --", "company_name")

    def test_detects_script_tag(self):
        from backend.security.input_validation import detect_injection
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            detect_injection("<script>alert(1)</script>", "company_name")

    def test_allows_normal_text(self):
        from backend.security.input_validation import detect_injection
        # Should not raise
        detect_injection("Recoxy Security Inc.", "company_name")
        detect_injection("Ada O'Brien", "last_name")


# ---------------------------------------------------------------------------
# SSRF Guard Tests
# ---------------------------------------------------------------------------

class TestSSRFGuard:
    def test_blocks_localhost(self):
        from backend.security.ssrf_guard import validate_scan_target
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            validate_scan_target("http://localhost/admin")
        assert "ssrf_blocked" in str(exc_info.value.detail)

    def test_blocks_127_0_0_1(self):
        from backend.security.ssrf_guard import validate_scan_target
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            validate_scan_target("http://127.0.0.1:8000/api")
        assert exc_info.value.status_code == 400

    def test_blocks_private_10_network(self):
        from backend.security.ssrf_guard import validate_scan_target
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            validate_scan_target("http://10.0.0.1/secret")

    def test_blocks_private_192_168_network(self):
        from backend.security.ssrf_guard import validate_scan_target
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            validate_scan_target("http://192.168.1.1/router")

    def test_blocks_file_scheme(self):
        from backend.security.ssrf_guard import validate_scan_target
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            validate_scan_target("file:///etc/passwd")
        assert "invalid_scheme" in str(exc_info.value.detail)

    def test_blocks_ftp_scheme(self):
        from backend.security.ssrf_guard import validate_scan_target
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            validate_scan_target("ftp://example.com/file.txt")

    def test_allows_public_https(self):
        from backend.security.ssrf_guard import validate_scan_target
        # Should not raise for a real public domain
        result = validate_scan_target("https://example.com")
        assert result == "https://example.com"

    def test_allows_public_http(self):
        from backend.security.ssrf_guard import validate_scan_target
        result = validate_scan_target("http://testphp.vulnweb.com")
        assert "testphp.vulnweb.com" in result


# ---------------------------------------------------------------------------
# JWT Guard Tests
# ---------------------------------------------------------------------------

class TestJWTGuard:
    def test_rejects_alg_none(self):
        """Ensure alg:none attack is blocked."""
        import base64, json
        from backend.security.jwt_guard import _verify_jwt
        from fastapi import HTTPException

        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "attacker", "role": "owner", "exp": 9999999999}).encode()).rstrip(b"=").decode()
        forged_token = f"{header}.{payload}."

        with pytest.raises(HTTPException) as exc_info:
            _verify_jwt(forged_token)
        assert "alg_none_rejected" in str(exc_info.value.detail)

    def test_rejects_expired_token(self):
        """Expired tokens must be rejected."""
        import base64, hashlib, hmac, json, time
        from backend.security.jwt_guard import JWT_SECRET, _verify_jwt
        from fastapi import HTTPException

        payload = {"sub": "user@test.com", "role": "owner", "exp": int(time.time()) - 3600}
        header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        signing_input = f"{header_b64}.{payload_b64}".encode()
        sig = base64.urlsafe_b64encode(hmac.new(JWT_SECRET, signing_input, hashlib.sha256).digest()).rstrip(b"=").decode()
        expired_token = f"{header_b64}.{payload_b64}.{sig}"

        with pytest.raises(HTTPException) as exc_info:
            _verify_jwt(expired_token)
        assert "token_expired" in str(exc_info.value.detail)

    def test_rejects_tampered_payload(self):
        """Tokens with modified payloads must fail signature check."""
        import base64, hashlib, hmac, json, time
        from backend.security.jwt_guard import JWT_SECRET, _verify_jwt
        from fastapi import HTTPException

        # Issue a valid token
        payload = {"sub": "user@test.com", "role": "viewer", "exp": int(time.time()) + 3600}
        header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        signing_input = f"{header_b64}.{payload_b64}".encode()
        sig = base64.urlsafe_b64encode(hmac.new(JWT_SECRET, signing_input, hashlib.sha256).digest()).rstrip(b"=").decode()

        # Tamper: change role to "owner" in payload
        tampered_payload = {"sub": "user@test.com", "role": "owner", "exp": int(time.time()) + 3600}
        tampered_b64 = base64.urlsafe_b64encode(json.dumps(tampered_payload).encode()).rstrip(b"=").decode()
        tampered_token = f"{header_b64}.{tampered_b64}.{sig}"

        with pytest.raises(HTTPException) as exc_info:
            _verify_jwt(tampered_token)
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# Rate Limiter Tests
# ---------------------------------------------------------------------------

class TestRateLimiter:
    def test_lockout_after_max_failures(self):
        from backend.security.rate_limiter import record_auth_failure, check_auth_lockout, clear_auth_failures, _lockout_states
        from fastapi import HTTPException
        from unittest.mock import MagicMock

        test_ip = "192.0.2.99"  # TEST-NET, safe for testing
        clear_auth_failures(test_ip)

        # Record 5 failures
        for _ in range(5):
            record_auth_failure(test_ip)

        mock_request = MagicMock()
        mock_request.client.host = test_ip
        mock_request.headers.get.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            check_auth_lockout(mock_request)
        assert exc_info.value.status_code == 429
        assert "locked" in str(exc_info.value.detail).lower()

        # Cleanup
        clear_auth_failures(test_ip)


# ---------------------------------------------------------------------------
# Route integration: weak password rejected at API level
# ---------------------------------------------------------------------------

class TestAuthRouteValidation:
    def test_register_weak_password_rejected(self):
        response = client.post("/api/auth/register", json={
            "first_name": "Test",
            "last_name": "User",
            "company_name": "Acme",
            "work_email": "test@example.com",
            "password": "weak",
            "confirm_password": "weak",
        })
        assert response.status_code == 400

    def test_register_short_password_rejected(self):
        response = client.post("/api/auth/register", json={
            "first_name": "Test",
            "last_name": "User",
            "company_name": "Acme",
            "work_email": "test@example.com",
            "password": "Short1!",          # 7 chars, < 12
            "confirm_password": "Short1!",
        })
        assert response.status_code == 400

    def test_scan_blocks_localhost_target(self):
        from tests.auth_helpers import admin_client
        response = admin_client.post("/api/scan", json={
            "target_url": "http://localhost/admin",
            "authorization_confirmed": True,
        })
        assert response.status_code == 400
        body = response.json()
        assert "ssrf_blocked" in str(body)

    def test_scan_blocks_private_ip(self):
        from tests.auth_helpers import admin_client
        response = admin_client.post("/api/scan", json={
            "target_url": "http://192.168.0.1/",
            "authorization_confirmed": True,
        })
        assert response.status_code == 400

    def test_health_endpoint_accessible(self):
        response = client.get("/api/health")
        assert response.status_code == 200

    def test_csrf_endpoint_returns_token(self):
        response = client.get("/api/auth/csrf")
        assert response.status_code == 200
        body = response.json()
        assert "csrf_token" in body
        assert len(body["csrf_token"]) > 32


# ---------------------------------------------------------------------------
# Deny-by-Default Middleware Tests
# ---------------------------------------------------------------------------

class TestDenyByDefault:
    def test_unauthenticated_request_blocked(self):
        """Verify deny-by-default middleware blocks unauthenticated access."""
        from fastapi.testclient import TestClient
        from backend.app import app
        anon = TestClient(app)
        response = anon.get("/api/reports")
        assert response.status_code == 401
        body = response.json()
        assert body["error"] == "not_authenticated"

    def test_public_routes_accessible(self):
        from fastapi.testclient import TestClient
        from backend.app import app
        anon = TestClient(app)
        assert anon.get("/api/health").status_code == 200
        assert anon.get("/api/auth/architecture").status_code == 200
        assert anon.get("/api/auth/csrf").status_code == 200

    def test_authenticated_request_passes(self):
        from tests.auth_helpers import admin_client
        response = admin_client.get("/api/reports")
        assert response.status_code == 200
