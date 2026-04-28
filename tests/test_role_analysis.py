from backend.core.role_analysis import compare_roles
from backend.database.db import save_scan


def test_role_comparison_flags_shared_privileged_endpoint(tmp_path, monkeypatch):
    from backend.database import db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "scanner.db")
    base = {
        "target_url": "https://example.test",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:00:01+00:00",
        "findings": [],
        "summary": {},
    }
    save_scan(base | {"scan_id": "user", "role_summary": {"role_name": "user"}, "endpoints": [{"method": "get", "url": "https://example.test/admin"}]})
    save_scan(base | {"scan_id": "admin", "role_summary": {"role_name": "admin"}, "endpoints": [{"method": "get", "url": "https://example.test/admin"}]})

    comparison = compare_roles("user", "admin")

    assert comparison is not None
    assert comparison["shared_endpoint_count"] == 1
    assert comparison["suspicious_shared_privileged_endpoints"]


def test_role_comparison_builds_idor_templates(tmp_path, monkeypatch):
    from backend.database import db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "scanner.db")
    base = {
        "target_url": "https://example.test",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:00:01+00:00",
        "findings": [],
        "summary": {},
    }
    save_scan(base | {"scan_id": "user-a", "role_summary": {"role_name": "user"}, "endpoints": [{"method": "get", "url": "https://example.test/api/orders/12"}]})
    save_scan(base | {"scan_id": "user-b", "role_summary": {"role_name": "admin"}, "endpoints": [{"method": "get", "url": "https://example.test/api/orders/99"}]})

    comparison = compare_roles("user-a", "user-b")

    assert comparison is not None
    assert comparison["idor_candidate_count"] == 1
    assert "{id}" in comparison["idor_candidates"][0]["template"]
