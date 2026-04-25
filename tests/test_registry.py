from backend.detection.registry import describe_loaded_detectors
from backend.detection.registry import load_detectors


def test_registry_loads_default_detectors():
    detectors = load_detectors()
    names = {detector.name for detector in detectors}
    assert {"sqli", "xss", "csrf", "auth_bypass"}.issubset(names)


def test_registry_describes_detector_metadata():
    descriptions = describe_loaded_detectors(["xss"])
    assert len(descriptions) == 1
    assert descriptions[0]["name"] == "xss"
    assert "dom" in descriptions[0]["supports"]
