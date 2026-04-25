from backend.core.request_handler import HttpResponse
from backend.core.response_analyzer import ResponseAnalyzer
from backend.payloads.payload_generator import PayloadGenerator


def test_xss_payloads_include_script_probe():
    assert any("script" in payload for payload in PayloadGenerator().xss_payloads())


def test_xss_probe_payloads_include_marker():
    marker = "awvs-marker"
    payloads = PayloadGenerator().xss_probe_payloads(marker)
    assert all(marker in payload for payload in payloads)


def test_response_analyzer_classifies_reflection_contexts():
    analyzer = ResponseAnalyzer()
    marker = "awvs-marker"
    response = HttpResponse(
        url="http://example.com",
        status_code=200,
        headers={},
        text=f'<script>{marker}</script><div data-x="{marker}">{marker}</div>',
        elapsed_ms=12.0,
    )
    reflection = analyzer.classify_reflection_context(response, marker)
    assert reflection["reflected"] is True
    assert "script" in reflection["contexts"]
    assert "attribute" in reflection["contexts"]
