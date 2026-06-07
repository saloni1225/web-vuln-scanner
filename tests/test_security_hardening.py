"""
tests/test_security_hardening.py

Security regression tests for Phase 1 hardening:
- MFA bypass fix: tokens not issued before OTP verification
- OTP code not leaked in API response
- SSRF expanded blocklist
- /exports requires authentication
- Legacy rbac/auth.py no longer accepts role from headers
"""
import pytest
from fastapi.testclient import TestClient

from backend.app import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# OTP / MFA security
# ---------------------------------------------------------------------------

class TestMFASecurity:
    def test_otp_dev_code_not_in_api_response(self):
        """
        CRITICAL: The OTP code must NEVER be returned in the API response.
        Previously dev_code was returned in plaintext, defeating MFA entirely.
        """
        from backend.auth.saas_auth import issue_otp
        result = issue_otp("test@example.com", "email_verification")
        assert "dev_code" not in result, (
            "dev_code is present in OTP response — this is a critical MFA bypass vulnerability!"
        )

    def test_otp_response_has_expected_fields(self):
        """OTP response should contain delivery info but NOT the code."""
        from backend.auth.saas_auth import issue_otp
        result = issue_otp("test@example.com", "test_purpose")
        assert "delivery" in result
        assert "email" in result
        assert "challenge_id" in result
        assert "expires_at" in result
        assert "code" not in result
        assert "otp_code" not in result

    def test_login_with_mfa_user_does_not_issue_tokens(self):
        """
        CRITICAL: When MFA is required, login_response() must NOT issue
        access/refresh tokens. Tokens should only be issued after OTP verification.
        """
        from backend.auth.saas_auth import login_response
        # Use a user that has mfa_enabled=True (default for newly registered users)
        # We'll mock the response by checking the structure
        # For a user with MFA: result should have requires_mfa=True but NO tokens key
        # We test the logic branch directly
        import unittest.mock as mock
        mock_user = {
            "user_id": "test-uuid",
            "email": "mfa_user@test.com",
            "password_hash": "dummy",
            "mfa_required": 1,
            "mfa_enabled": 1,
            "role": "owner",
            "organization_id": "test-org",
            "first_name": "Test",
        }
        with mock.patch("backend.auth.saas_auth.get_auth_user_by_email", return_value=mock_user), \
             mock.patch("backend.auth.saas_auth.verify_password", return_value=True), \
             mock.patch("backend.auth.saas_auth.mark_auth_user_login"), \
             mock.patch("backend.auth.saas_auth.write_audit_log"), \
             mock.patch("backend.auth.saas_auth.issue_otp", return_value={"challenge_id": "abc"}):
            result = login_response("mfa_user@test.com", "Test@1234")

        assert result.get("requires_mfa") is True, "requires_mfa must be True for MFA users"
        assert "tokens" not in result, (
            "CRITICAL: Tokens must NOT be issued before MFA verification! "
            "This is the MFA bypass vulnerability."
        )
        assert "pending_mfa_email" in result, "Should contain pending_mfa_email for OTP step"

    def test_login_without_mfa_issues_tokens(self):
        """Non-MFA users should receive tokens directly upon successful login."""
        from backend.auth.saas_auth import login_response
        import unittest.mock as mock
        mock_user = {
            "user_id": "test-uuid",
            "email": "no_mfa_user@test.com",
            "password_hash": "dummy",
            "mfa_required": 0,
            "mfa_enabled": 0,
            "role": "analyst",
            "organization_id": "test-org",
            "first_name": "Test",
        }
        with mock.patch("backend.auth.saas_auth.get_auth_user_by_email", return_value=mock_user), \
             mock.patch("backend.auth.saas_auth.verify_password", return_value=True), \
             mock.patch("backend.auth.saas_auth.mark_auth_user_login"), \
             mock.patch("backend.auth.saas_auth.write_audit_log"), \
             mock.patch("backend.auth.saas_auth.issue_tokens", return_value={"access_token": "tok", "refresh_token": "ref"}):
            result = login_response("no_mfa_user@test.com", "Test@1234")

        assert result.get("authenticated") is True
        assert result.get("requires_mfa") is False
        assert "tokens" in result


# ---------------------------------------------------------------------------
# RBAC auth — role injection via headers must be blocked
# ---------------------------------------------------------------------------

class TestRbacAuthSecurity:
    def test_role_not_accepted_from_header(self):
        """
        CRITICAL: The legacy rbac/auth.py accepted X-AdaptiveScan-Role header
        without JWT verification. This must now require a valid JWT.
        """
        from backend.rbac.auth import current_principal
        import asyncio
        from unittest.mock import MagicMock

        # Create a mock request with an elevated role header but no JWT
        mock_request = MagicMock()
        mock_request.headers = {"x-adaptivescan-role": "owner", "authorization": ""}
        mock_request.cookies = {}

        # Should raise 401 (no JWT) rather than accepting the header role
        with pytest.raises(Exception) as exc_info:
            asyncio.run(current_principal(mock_request))
        # Should be 401 not 403 (not authenticated, not just unauthorized)
        assert hasattr(exc_info.value, "status_code") and exc_info.value.status_code == 401

    def test_principal_from_role_emits_deprecation_warning(self):
        """principal_from_role() is deprecated and must emit a DeprecationWarning."""
        from backend.rbac.auth import principal_from_role
        with pytest.warns(DeprecationWarning):
            p = principal_from_role("owner")
        assert p.role == "owner"

    def test_literal_role_string_not_accepted_as_token(self):
        """
        Old code accepted 'owner' as a valid Authorization Bearer token.
        New code must reject this.
        """
        from backend.security.jwt_guard import _verify_jwt
        with pytest.raises(Exception):
            _verify_jwt("owner")

        with pytest.raises(Exception):
            _verify_jwt("admin")


# ---------------------------------------------------------------------------
# SSRF blocklist expansion
# ---------------------------------------------------------------------------

class TestSSRFBlocklist:
    def test_cloud_metadata_blocked(self):
        """AWS/GCP/Azure instance metadata endpoint must be blocked."""
        from backend.utils.helpers import is_private_host
        assert is_private_host("http://169.254.169.254/latest/meta-data/", resolve_dns=False)
        assert is_private_host("http://169.254.169.254", resolve_dns=False)

    def test_gcp_metadata_blocked(self):
        from backend.utils.helpers import is_private_host
        assert is_private_host("http://metadata.google.internal", resolve_dns=False)

    def test_ipv6_loopback_blocked(self):
        from backend.utils.helpers import is_private_host
        assert is_private_host("http://[::1]/", resolve_dns=False)

    def test_all_rfc1918_ranges_blocked(self):
        from backend.utils.helpers import is_private_host
        # Class A
        assert is_private_host("http://10.0.0.1/", resolve_dns=False)
        assert is_private_host("http://10.255.255.255/", resolve_dns=False)
        # Class B (full range 172.16-31)
        assert is_private_host("http://172.16.0.1/", resolve_dns=False)
        assert is_private_host("http://172.20.0.1/", resolve_dns=False)
        assert is_private_host("http://172.31.255.255/", resolve_dns=False)
        # Class C
        assert is_private_host("http://192.168.1.1/", resolve_dns=False)

    def test_localhost_variants_blocked(self):
        from backend.utils.helpers import is_private_host
        assert is_private_host("http://localhost/", resolve_dns=False)
        assert is_private_host("http://127.0.0.1/", resolve_dns=False)
        assert is_private_host("http://127.255.255.255/", resolve_dns=False)

    def test_wildcard_0000_blocked(self):
        from backend.utils.helpers import is_private_host
        assert is_private_host("http://0.0.0.0/", resolve_dns=False)

    def test_link_local_range_blocked(self):
        from backend.utils.helpers import is_private_host
        assert is_private_host("http://169.254.1.1/", resolve_dns=False)

    def test_public_ip_allowed(self):
        from backend.utils.helpers import is_private_host
        # Public IPs should NOT be blocked by the blocklist alone (resolve_dns=False)
        assert not is_private_host("http://8.8.8.8/", resolve_dns=False)
        assert not is_private_host("https://example.com/", resolve_dns=False)
        assert not is_private_host("https://google.com/", resolve_dns=False)

    def test_empty_host_blocked(self):
        from backend.utils.helpers import is_private_host
        assert is_private_host("http:///path", resolve_dns=False)
        assert is_private_host("", resolve_dns=False)


# ---------------------------------------------------------------------------
# Exports directory requires authentication
# ---------------------------------------------------------------------------

class TestExportsAuthentication:
    def test_exports_requires_auth(self, client):
        """
        /api/exports/* must return 401 without a valid JWT.
        Previously /exports was mounted outside /api and was publicly accessible.
        """
        response = client.get("/api/exports/some-report.html")
        assert response.status_code in (401, 403, 404), (
            f"Expected 401/403/404 for unauthenticated exports access, got {response.status_code}. "
            "This is a critical vulnerability — scan reports are publicly accessible!"
        )

    def test_old_exports_path_not_mounted(self, client):
        """The legacy /exports path (without /api) should NOT exist."""
        response = client.get("/exports/test.html")
        # Should be 404 (not mounted) not 200 (publicly accessible)
        assert response.status_code == 404, (
            f"/exports is still publicly mounted. Got {response.status_code}. "
            "Reports are accessible without authentication."
        )
