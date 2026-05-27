from __future__ import annotations

from datetime import datetime, timezone

from backend.config.settings import settings
from backend.queue.orchestrator import QUEUE_DEFINITIONS, queue_health_snapshot, queue_topology


def worker_pool_status() -> dict[str, object]:
    topology = queue_topology()
    pools = []
    for queue in QUEUE_DEFINITIONS:
        desired = int(queue["desired_concurrency"])
        pools.append(
            {
                "name": queue["name"],
                "queue": queue["name"],
                "routing_key": queue["routing_key"],
                "desired_concurrency": desired,
                "autoscaling": {"min": 1, "max": max(desired * 3, desired)},
                "heartbeat": {
                    "status": "ready",
                    "last_seen_at": datetime.now(timezone.utc).isoformat(),
                    "stale_after_seconds": 45,
                },
                "status": "ready",
            }
        )
    return {
        "mode": settings.execution_mode,
        "broker": topology["broker"],
        "worker_runtime": topology["worker_runtime"],
        "worker_pools": pools,
        "queue_health": queue_health_snapshot(),
        "scale_policy": {
            "metric": "queued_tasks_per_pool",
            "scale_out_threshold": 25,
            "scale_in_after_idle_seconds": 300,
        },
    }


def worker_heartbeat(worker_id: str, pool: str, active_task_count: int = 0) -> dict[str, object]:
    known_pools = {str(queue["name"]) for queue in QUEUE_DEFINITIONS}
    return {
        "worker_id": worker_id,
        "pool": pool if pool in known_pools else "unknown",
        "status": "ready" if pool in known_pools else "unregistered",
        "active_task_count": max(0, active_task_count),
        "last_seen_at": datetime.now(timezone.utc).isoformat(),
    }
