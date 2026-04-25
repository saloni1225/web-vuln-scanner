from backend.detection.sqli_detector import SQLiDetector
from backend.core.request_handler import HttpResponse
from backend.core.response_analyzer import ResponseAnalyzer


def test_sqli_detector_has_name():
    assert SQLiDetector().name == "sqli"


def test_response_analyzer_flags_boolean_delta():
    analyzer = ResponseAnalyzer()
    baseline = HttpResponse(url="http://example.com", status_code=200, headers={}, text="normal response", elapsed_ms=80)
    truthy = HttpResponse(url="http://example.com", status_code=200, headers={}, text="normal response with 10 records", elapsed_ms=95)
    falsy = HttpResponse(url="http://example.com", status_code=200, headers={}, text="no records", elapsed_ms=92)
    assert analyzer.has_boolean_response_delta(baseline, truthy, falsy) is True


def test_response_analyzer_flags_time_delay():
    analyzer = ResponseAnalyzer()
    baseline = HttpResponse(url="http://example.com", status_code=200, headers={}, text="ok", elapsed_ms=120)
    delayed = HttpResponse(url="http://example.com", status_code=200, headers={}, text="ok", elapsed_ms=4800)
    assert analyzer.has_time_delay_anomaly(baseline, delayed) is True

