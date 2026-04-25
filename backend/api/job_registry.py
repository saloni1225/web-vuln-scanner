from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(slots=True)
class ScanJobState:
    scan_id: str
    target_url: str
    status: str
    progress: int
    created_at: str
    updated_at: str
    message: str = ""
    queue_position: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "status": self.status,
            "progress": self.progress,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "message": self.message,
            "queue_position": self.queue_position,
        }


class ScanJobRegistry:
    def __init__(self) -> None:
        self._jobs: dict[str, ScanJobState] = {}

    def register(self, scan_id: str, target_url: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        queue_position = sum(1 for job in self._jobs.values() if job.status in {"queued", "running"}) + 1
        self._jobs[scan_id] = ScanJobState(
            scan_id=scan_id,
            target_url=target_url,
            status="queued",
            progress=0,
            created_at=now,
            updated_at=now,
            message=f"Queued scan for {target_url}",
            queue_position=queue_position,
        )

    def update(self, scan_id: str, *, status: str | None = None, progress: int | None = None, message: str | None = None) -> None:
        job = self._jobs.get(scan_id)
        if not job:
            return
        if status is not None:
            job.status = status
        if progress is not None:
            job.progress = progress
        if message is not None:
            job.message = message
        job.updated_at = datetime.now(timezone.utc).isoformat()
        if job.status in {"running", "completed", "failed"}:
            job.queue_position = None

    def list_jobs(self) -> list[dict[str, object]]:
        return [job.to_dict() for job in sorted(self._jobs.values(), key=lambda item: item.created_at, reverse=True)]


job_registry = ScanJobRegistry()
