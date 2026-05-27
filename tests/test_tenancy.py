from backend.database import db


def test_tenancy_overview_tracks_org_workspace_and_api_key(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "scanner.db")

    org = db.create_organization("Acme Security", plan="enterprise", actor="owner@example.test")
    workspace = db.create_workspace(
        org["org_id"],
        "Production Apps",
        default_allowlist=["example.test"],
        actor="owner@example.test",
    )
    api_key = db.create_api_key(
        workspace["workspace_id"],
        "GitHub Actions",
        scopes=["scan:run", "report:read"],
        actor="owner@example.test",
    )

    assert api_key["secret"].startswith("ascan_")
    assert api_key["key_prefix"] in api_key["secret"]

    overview = db.get_tenancy_overview()
    assert overview["organizations"][0]["name"] == "Acme Security"
    assert overview["workspaces"][0]["default_allowlist"] == ["example.test"]
    assert overview["api_keys"][0]["name"] == "GitHub Actions"
    assert "secret" not in overview["api_keys"][0]
    assert {role["role"] for role in overview["rbac_roles"]} >= {"owner", "analyst", "viewer", "ci-bot"}

    audit_events = [item["event_type"] for item in db.list_audit_logs(limit=10)]
    assert audit_events[:3] == ["api_key.created", "workspace.created", "organization.created"]
