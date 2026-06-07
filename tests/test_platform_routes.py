from tests.auth_helpers import admin_client as client


def test_platform_routes_are_integrated():
    health = client.get("/api/health")
    overview = client.get("/api/platform/overview")
    operations = client.get("/api/platform/operations")
    ai_intelligence = client.get("/api/platform/ai-intelligence")
    monitoring = client.get("/api/platform/monitoring")
    workers = client.get("/api/platform/workers")

    assert health.status_code == 200
    assert overview.status_code == 200
    assert overview.json()["product"] == "AdaptiveScan"
    assert operations.status_code == 200
    assert operations.json()["executive"]["organization_exposure_score"] >= 0
    assert "exposure_operations" in operations.json()
    assert "offensive_research" in operations.json()
    assert "ai_offensive_intelligence" in operations.json()
    assert "attack_path_analysis" in operations.json()
    assert "drift_intelligence" in operations.json()
    assert "operational_telemetry" in operations.json()
    assert ai_intelligence.status_code == 200
    assert ai_intelligence.json()["runtime"]["hf_ready"] is True
    assert monitoring.status_code == 200
    assert monitoring.json()["alert_policies"]
    assert workers.status_code == 200
    assert workers.json()["worker_pools"]
