from dataclasses import dataclass


@dataclass(slots=True)
class ScanRecord:
    scan_id: str
    target_url: str
    started_at: str
    finished_at: str
    findings_count: int

