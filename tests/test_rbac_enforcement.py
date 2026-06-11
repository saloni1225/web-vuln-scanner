"""
tests/test_rbac_enforcement.py

Regression tests for Phase 6 RBAC hardening.
Verifies that:
- viewer_client is BLOCKED (403 Forbidden) from POST /scan, scan resume, finding lifecycle updates, comments, and replay.
- owner_client is ALLOWED (bypasses 403 Forbidden RBAC gate) to perform these operations.
"""
import pytest
from unittest.mock import patch

from tests.auth_helpers import authenticated_client


def test_viewer_is_blocked_from_mutating_actions():
    """Viewer role must be blocked (403) from launching scans, writing comments, lifecycle state changes, and replay."""
    client = authenticated_client("viewer")

    # 1. Blocked from scan launch
    resp = client.post("/api/scan", json={"target_url": "http://example.com"})
    assert resp.status_code == 403

    # 2. Blocked from scan resume
    resp = client.post("/api/scans/some-scan-id/resume")
    assert resp.status_code == 403

    # 3. Blocked from finding lifecycle writes
    resp = client.put("/api/findings/some-scan-id/0/lifecycle", json={"state": "assigned"})
    assert resp.status_code == 403

    # 4. Blocked from adding comments
    resp = client.post("/api/findings/some-scan-id/0/comments", json={"body": "test comment"})
    assert resp.status_code == 403

    # 5. Blocked from finding replay (export:read scope required)
    resp = client.get("/api/replay/some-scan-id/0")
    assert resp.status_code == 403


def test_owner_is_allowed_mutating_actions():
    """Owner role must bypass the RBAC gate (no 403). Operations may fail downstream (404/400) but not 403."""
    client = authenticated_client("owner")

    # 1. Scan launch should pass RBAC gate and run validation (mocked to succeed)
    with patch("backend.api.routes.validate_scan_target") as mock_validate, \
         patch("backend.api.routes.controller.start_scan", return_value={"scan_id": "test-id"}) as mock_start, \
         patch("backend.api.routes.controller.create_report_bundle", return_value=[]) as mock_bundle, \
         patch("backend.api.routes.controller.create_report_urls", return_value={"html": "", "pdf": ""}) as mock_urls, \
         patch("backend.api.routes.save_scan"):
        resp = client.post("/api/scan", json={"target_url": "http://8.8.8.8", "authorization_confirmed": True})
        assert resp.status_code != 403

    # 2. Scan resume should pass RBAC and fail with 404 (missing report), not 403
    resp = client.post("/api/scans/missing-scan-id/resume")
    assert resp.status_code == 404

    # 3. Lifecycle change should pass RBAC and fail with 404, not 403
    resp = client.put("/api/findings/missing-scan-id/0/lifecycle", json={"state": "assigned"})
    assert resp.status_code == 404

    # 4. Comments should pass RBAC and fail with 404, not 403
    resp = client.post("/api/findings/missing-scan-id/0/comments", json={"body": "test comment"})
    assert resp.status_code == 404

    # 5. Replay should pass RBAC and fail with 404, not 403
    resp = client.get("/api/replay/missing-scan-id/0")
    assert resp.status_code == 404


def test_new_admin_and_read_rbac_enforcement():
    """Verify newly protected admin and informational endpoints behave correctly under RBAC."""
    viewer = authenticated_client("viewer")
    owner = authenticated_client("owner")

    # 1. Viewer must be blocked (403) from admin endpoints
    assert viewer.post("/api/organizations", json={"name": "test org"}).status_code == 403
    assert viewer.post("/api/workspaces", json={"org_id": "test-org", "name": "test ws"}).status_code == 403
    assert viewer.post("/api/api-keys", json={"workspace_id": "test-ws", "name": "test key"}).status_code == 403
    assert viewer.get("/api/audit-logs").status_code == 403
    assert viewer.get("/api/tenancy/overview").status_code == 403

    # 2. Viewer must be allowed (no 403) on informational scan:read endpoints
    assert viewer.get("/api/detectors").status_code != 403
    assert viewer.get("/api/scan-profiles").status_code != 403
    assert viewer.get("/api/platform/overview").status_code != 403
    assert viewer.get("/api/platform/lifecycle-policy").status_code != 403
    assert viewer.get("/api/platform/monitoring").status_code != 403

    # 3. Owner must be allowed (no 403) on admin endpoints
    with patch("backend.api.routes.create_organization", return_value={}) as mock_create_org, \
         patch("backend.api.routes.create_workspace", return_value={}) as mock_create_ws, \
         patch("backend.api.routes.create_api_key", return_value={}) as mock_create_key:
        assert owner.post("/api/organizations", json={"name": "test org"}).status_code != 403
        assert owner.post("/api/workspaces", json={"org_id": "test-org", "name": "test ws"}).status_code != 403
        assert owner.post("/api/api-keys", json={"workspace_id": "test-ws", "name": "test key"}).status_code != 403

    assert owner.get("/api/audit-logs").status_code != 403
    assert owner.get("/api/tenancy/overview").status_code != 403


def test_secondary_endpoints_rbac_enforcement():
    """Verify that billing subscription/usage, team, sso, and founder analytics are correctly protected under RBAC."""
    viewer = authenticated_client("viewer")
    analyst = authenticated_client("analyst")
    owner = authenticated_client("owner")

    # 1. Viewer is blocked (403) from org/workspace admin & billing & sso endpoints
    assert viewer.get("/api/billing/subscription").status_code == 403
    assert viewer.get("/api/billing/usage").status_code == 403
    assert viewer.get("/api/billing/stripe").status_code == 403
    assert viewer.get("/api/team").status_code == 403
    assert viewer.get("/api/sso/providers").status_code == 403
    assert viewer.get("/api/sso/configuration").status_code == 403
    assert viewer.get("/api/founder/analytics").status_code == 403

    # 2. Viewer is allowed on catalog and monitoring (has monitoring:read, workspace:read, etc.)
    assert viewer.get("/api/billing/catalog").status_code != 403
    assert viewer.get("/api/notifications").status_code != 403
    assert viewer.get("/api/monitoring/workflows").status_code != 403
    assert viewer.get("/api/monitoring/scheduler").status_code != 403
    assert viewer.get("/api/monitoring/jobs").status_code != 403

    # 3. Analyst is blocked (403) from org admin, billing, sso, and team (needs org:admin, workspace:admin, rbac:admin)
    assert analyst.get("/api/billing/subscription").status_code == 403
    assert analyst.get("/api/team").status_code == 403
    assert analyst.get("/api/sso/providers").status_code == 403
    assert analyst.get("/api/founder/analytics").status_code == 403

    # 4. Owner has full permissions (no 403)
    assert owner.get("/api/billing/subscription").status_code != 403
    assert owner.get("/api/billing/usage").status_code != 403
    assert owner.get("/api/billing/stripe").status_code != 403
    assert owner.get("/api/team").status_code != 403
    assert owner.get("/api/sso/providers").status_code != 403
    assert owner.get("/api/sso/configuration").status_code != 403
    assert owner.get("/api/founder/analytics").status_code != 403
