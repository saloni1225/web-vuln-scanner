from fastapi.testclient import TestClient

from backend.app import app


client = TestClient(app)


def test_public_api_catalog_and_marketplace_architecture():
    catalog = client.get("/api/public-api/catalog")
    marketplace = client.get("/api/marketplace/architecture")
    report = client.get("/api/implementation/report")

    assert catalog.status_code == 200
    resources = {resource["name"] for resource in catalog.json()["resources"]}
    assert {"Assets API", "Findings API", "Reports API", "Monitoring API", "Notifications API"} <= resources

    assert marketplace.status_code == 200
    assert "Slack" in marketplace.json()["connectors"]
    assert marketplace.json()["integration_model"]["approval"].startswith("organization admin")

    assert report.status_code == 200
    assert report.json()["operating_model"] == ["Organization", "Assets", "Monitoring", "Exposure", "Findings", "Reports"]


def test_public_resource_apis_and_founder_analytics():
    assets = client.get("/api/public/assets")
    findings = client.get("/api/public/findings")
    reports = client.get("/api/public/reports")
    monitoring = client.get("/api/public/monitoring")
    notifications = client.get("/api/public/notifications")
    founder = client.get("/api/founder/analytics")

    assert assets.status_code == 200
    assert "relationships" in assets.json()
    assert findings.status_code == 200
    assert "findings" in findings.json()
    assert reports.status_code == 200
    assert "reports" in reports.json()
    assert monitoring.status_code == 200
    assert monitoring.json()["operating_model"] == ["organization", "assets", "monitoring", "exposure", "findings", "reports"]
    assert notifications.status_code == 200
    assert notifications.json()["channels"]
    assert founder.status_code == 200
    assert {"revenue", "growth", "platform_usage", "founder_view"} <= set(founder.json())
