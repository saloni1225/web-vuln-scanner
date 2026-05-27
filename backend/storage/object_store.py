from __future__ import annotations

from pathlib import Path

from backend.config.settings import ROOT_DIR


OBJECT_STORE_ROOT = ROOT_DIR / "backend" / "reports" / "exports"


def object_storage_status() -> dict[str, object]:
    OBJECT_STORE_ROOT.mkdir(parents=True, exist_ok=True)
    files = list(Path(OBJECT_STORE_ROOT).glob("*"))
    return {
        "provider": "local-filesystem",
        "path": str(OBJECT_STORE_ROOT),
        "artifact_count": len(files),
        "upgrade_path": ["S3-compatible object storage", "signed URLs", "evidence bundle retention policies"],
    }

