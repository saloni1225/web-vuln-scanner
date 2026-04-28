import json
from pathlib import Path

from backend.config.settings import ROOT_DIR


STATE_DIR = ROOT_DIR / "backend" / ".scan_state"


def save_checkpoint(scan_id: str, phase: str, payload: dict[str, object]) -> Path:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = STATE_DIR / f"{scan_id}.json"
    data = load_checkpoint(scan_id) or {}
    data[phase] = payload
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def load_checkpoint(scan_id: str) -> dict[str, object] | None:
    path = STATE_DIR / f"{scan_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
