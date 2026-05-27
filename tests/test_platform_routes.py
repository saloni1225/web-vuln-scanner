from fastapi.testclient import TestClient

from backend.app import app


def test_platform_routes_are_integrated():
    client = TestClient(app)
    health = client.get("/api/health")
    overview = client.get("/api/platform/overview")
    operations = client.get("/api/platform/operations")
    monitoring = client.get("/api/platform/monitoring")
    workers = client.get("/api/platform/workers")

    assert health.status_code == 200
    assert overview.status_code == 200
    assert overview.json()["product"] == "AdaptiveScan"
    assert operations.status_code == 200
    assert operations.json()["executive"]["organization_exposure_score"] >= 0
    assert "exposure_operations" in operations.json()
    assert "offensive_research" in operations.json()
    assert monitoring.status_code == 200
    assert monitoring.json()["alert_policies"]
    assert workers.status_code == 200
    assert workers.json()["worker_pools"]
