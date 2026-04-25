from backend.detection.sqli_detector import SQLiDetector


def test_sqli_detector_has_name():
    assert SQLiDetector().name == "sqli"

