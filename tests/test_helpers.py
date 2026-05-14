from backend.utils.helpers import build_target_advisory
from backend.utils.helpers import map_cwe


def test_map_cwe_uses_detector_defaults():
    sqli = map_cwe("sqli")
    assert sqli["cwe_id"] == "CWE-89"
    xss = map_cwe("xss")
    assert xss["cwe_id"] == "CWE-79"


def test_external_target_advisory_supports_authorized_hosted_scans():
    advisory = build_target_advisory("https://staging.example.com")
    assert advisory["kind"] == "external"
    assert advisory["safe_for_demo"] is False
    assert "Hosted targets are supported" in advisory["message"]


def test_local_target_advisory_is_not_lab_specific():
    advisory = build_target_advisory("http://127.0.0.1:3000")
    assert advisory["kind"] == "local-or-private"
    assert advisory["safe_for_demo"] is True
    assert "Juice Shop" not in advisory["message"]
