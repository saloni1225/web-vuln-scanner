from backend.database.migrations import database_backend_status
from backend.observability.service import observability_status, prometheus_metrics
from backend.queue.orchestrator import build_distributed_execution_plan, build_scan_job, queue_health_snapshot, route_scan_job
from backend.workers.scan_worker import worker_heartbeat, worker_pool_status
from tests.auth_helpers import admin_client as client


def test_distributed_queue_routing_and_execution_plan_are_deterministic():
    options = {"enable_subdomain_recon": True, "enable_finding_validator": True}
    job = build_scan_job("scan-1", "https://example.com", options)
    plan = build_distributed_execution_plan("scan-1", "https://example.com", options)

    assert route_scan_job(options) == "recon"
    assert job["queue"] == "recon"
    assert [step["phase"] for step in plan] == ["recon", "crawl", "detect", "validate", "ai", "report"]
    assert plan[2]["detector_scope"] == "web-api-detectors"


def test_worker_and_queue_health_expose_enterprise_fleet_metadata():
    status = worker_pool_status()
    heartbeat = worker_heartbeat("worker-1", "detect", active_task_count=3)
    health = queue_health_snapshot([{"queue": "detect"}, {"queue": "detect"}])

    assert status["worker_runtime"] == "celery"
    assert {pool["name"] for pool in status["worker_pools"]} >= {"recon", "crawl", "detect", "validate", "report", "ai"}
    assert heartbeat["status"] == "ready"
    assert next(queue for queue in health["queues"] if queue["name"] == "detect")["queued"] == 2


def test_database_and_observability_platform_surfaces():
    db_status = database_backend_status()
    obs = observability_status()
    metrics = prometheus_metrics([{"findings_count": 2, "high_severity_count": 1}], {"queues": [{"name": "crawl", "queued": 4}]})

    assert db_status["migration_tool"] == "alembic"
    assert len(db_status["migration_plan"]) >= 4
    assert obs["prometheus"]["endpoint"] == "/api/metrics"
    assert 'adaptivescan_queue_depth{queue="crawl"} 4' in metrics


def test_platform_routes_expose_distributed_operational_state():
    queue = client.get("/api/platform/queue")
    database = client.get("/api/platform/database")
    observability = client.get("/api/platform/observability")
    metrics = client.get("/api/metrics")
    heartbeat = client.post("/api/workers/worker-1/heartbeat?pool=detect&active_task_count=2")

    assert queue.status_code == 200
    assert queue.json()["health"]["status"] == "ready"
    assert database.status_code == 200
    assert database.json()["migration_tool"] == "alembic"
    assert observability.status_code == 200
    assert observability.json()["prometheus"]["enabled"] is True
    assert metrics.status_code == 200
    assert "adaptivescan_scans_total" in metrics.text
    assert heartbeat.json()["active_task_count"] == 2
