from __future__ import annotations

from backend.config.settings import settings


ALEMBIC_REVISION_PLAN: list[dict[str, object]] = [
    {
        "revision": "0001_enterprise_core",
        "description": "organizations, workspaces, members, api keys, audit logs",
        "tables": ["organizations", "workspaces", "team_members", "api_keys", "audit_logs"],
    },
    {
        "revision": "0002_scan_partitions",
        "description": "tenant-aware scans, summaries, lifecycle, findings partitioning metadata",
        "tables": ["scans", "finding_lifecycle", "scan_artifacts"],
    },
    {
        "revision": "0003_attack_surface_graph",
        "description": "assets, services, endpoints, graph edges, drift events",
        "tables": ["assets", "asset_edges", "exposure_events", "technology_inventory"],
    },
    {
        "revision": "0004_distributed_execution",
        "description": "scan jobs, task attempts, worker heartbeats, queue telemetry",
        "tables": ["scan_jobs", "task_attempts", "worker_heartbeats", "queue_metrics"],
    },
]


def database_backend_status() -> dict[str, object]:
    url = settings.database_url
    if url.startswith("postgresql"):
        engine = "postgresql"
        driver = "asyncpg" if "+asyncpg" in url else "psycopg"
        mode = "enterprise"
    elif url.startswith("sqlite"):
        engine = "sqlite"
        driver = "sqlite3"
        mode = "local-dev"
    else:
        engine = "unknown"
        driver = "unknown"
        mode = "custom"
    return {
        "engine": engine,
        "driver": driver,
        "mode": mode,
        "database_url_configured": bool(url),
        "tenant_isolation": "workspace_id scoped rows with RBAC enforcement points",
        "partitioning_strategy": "findings and telemetry partitioned by finished_at month in PostgreSQL mode",
        "indexes": [
            "idx_scans_target_started",
            "idx_scans_workspace_started",
            "idx_findings_scan_severity",
            "idx_assets_workspace_host",
            "idx_audit_created_at",
        ],
        "migration_tool": "alembic",
        "migration_plan": ALEMBIC_REVISION_PLAN,
    }

