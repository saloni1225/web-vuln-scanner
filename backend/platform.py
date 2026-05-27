from __future__ import annotations

from urllib.parse import urlparse

from backend.audit.events import audit_event_catalog
from backend.auth.session_models import authenticated_scan_capabilities
from backend.metrics.service import platform_metrics
from backend.monitoring.policies import monitoring_overview
from backend.database.migrations import database_backend_status
from backend.observability.service import observability_status
from backend.payload_engine.catalog import payload_catalog
from backend.queue.orchestrator import queue_topology
from backend.rbac.policy import rbac_overview
from backend.storage.object_store import object_storage_status
from backend.attack_surface.graph import build_drift_timeline
from backend.exposure.intelligence import aggregate_exposure
from backend.operations.intelligence import build_operations_intelligence
from backend.workers.scan_worker import worker_pool_status


def build_platform_overview(scans: list[dict[str, object]]) -> dict[str, object]:
    hosts = sorted({urlparse(str(scan.get("target_url", ""))).hostname or str(scan.get("target_url", "")) for scan in scans})
    return {
        "product": "AdaptiveScan",
        "positioning": "AI-assisted continuous attack surface and application security intelligence platform",
        "architecture": {
            "frontend": "React/Vite enterprise dashboard",
            "api_gateway": "FastAPI",
            "queue": queue_topology(),
            "workers": worker_pool_status(),
            "database": database_backend_status(),
            "object_storage": object_storage_status(),
            "telemetry": "websocket events, scan timelines, detector timings",
            "ai_risk_engine": "local deterministic prioritization with LLM-ready remediation hooks",
            "observability": observability_status(),
        },
        "metrics": platform_metrics(scans),
        "monitoring": monitoring_overview(scans),
        "assets": {"tracked_hosts": hosts, "host_count": len(hosts)},
        "attack_surface_intelligence": {
            "drift": build_drift_timeline(scans),
            "exposure": aggregate_exposure(scans),
            "model": "organization -> infrastructure -> exposure -> attack paths -> exploitability",
            "capabilities": [
                "attack graph",
                "API relationship mapping",
                "auth surface correlation",
                "cloud exposure candidates",
                "continuous drift analytics",
            ],
        },
        "operations_intelligence": build_operations_intelligence(scans),
        "security": {
            "headers": ["CSP", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"],
            "controls": ["authorization confirmation", "domain allowlists", "rate limiting", "safe replay", "audit logs"],
        },
        "auth": authenticated_scan_capabilities(),
        "rbac": rbac_overview(),
        "audit": audit_event_catalog(),
        "payloads": payload_catalog(),
        "distributed_execution": {
            "queue_health": worker_pool_status().get("queue_health", {}),
            "worker_fleet": worker_pool_status().get("worker_pools", []),
        },
    }
