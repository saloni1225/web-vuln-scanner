import json
from importlib import import_module
from pathlib import Path

from backend.config.settings import ROOT_DIR
from backend.detection.base_detector import BaseDetector


REGISTRY_PATH = ROOT_DIR / "backend" / "detection" / "detectors.json"


def load_detector_specs() -> list[dict[str, object]]:
    with REGISTRY_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    detectors = payload.get("detectors", [])
    if not isinstance(detectors, list):
        return []
    return [item for item in detectors if isinstance(item, dict)]


def load_detectors(enabled_names: list[str] | None = None) -> list[BaseDetector]:
    requested = {name.lower() for name in (enabled_names or []) if name}
    detectors: list[BaseDetector] = []
    for spec in load_detector_specs():
        name = str(spec.get("name", "")).lower()
        if requested and name not in requested:
            continue
        if spec.get("enabled") is False:
            continue
        module = import_module(str(spec["module"]))
        detector_class = getattr(module, str(spec["class"]))
        detectors.append(detector_class())
    return detectors


def describe_loaded_detectors(enabled_names: list[str] | None = None) -> list[dict[str, object]]:
    requested = {name.lower() for name in (enabled_names or []) if name}
    descriptions: list[dict[str, object]] = []
    for spec in load_detector_specs():
        name = str(spec.get("name", "")).lower()
        if requested and name not in requested:
            continue
        descriptions.append(
            {
                "name": spec.get("name"),
                "enabled": bool(spec.get("enabled", True)),
                "category": spec.get("category", "generic"),
                "description": spec.get("description", ""),
                "supports": spec.get("supports", []),
            }
        )
    return descriptions
