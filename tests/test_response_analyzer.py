from backend.core.request_handler import HttpResponse
from backend.core.response_analyzer import ResponseAnalyzer


def test_response_analyzer_summarizes_diff_and_anomaly_score():
    analyzer = ResponseAnalyzer()
    baseline = HttpResponse(
        url="http://example.com",
        status_code=200,
        headers={"content-type": "text/html"},
        text="baseline body",
        elapsed_ms=100.0,
    )
    candidate = HttpResponse(
        url="http://example.com?q=test",
        status_code=500,
        headers={"content-type": "text/html", "x-debug": "1"},
        text="changed body with much more content than baseline",
        elapsed_ms=4100.0,
    )
    diff = analyzer.summarize_response_diff(baseline, candidate)
    assert diff["status_changed"] is True
    assert diff["length_delta"] > 0
    assert analyzer.anomaly_score(baseline, candidate) > 0.5


def test_response_analyzer_classifies_confidence_from_multiple_signals():
    analyzer = ResponseAnalyzer()
    confidence = analyzer.classify_confidence(
        error_signature=True,
        boolean_delta=True,
        anomaly_score=0.7,
    )
    assert confidence["confidence"] == "high"
    assert confidence["confidence_score"] >= 0.75
    assert "error-signature" in confidence["signals"]
