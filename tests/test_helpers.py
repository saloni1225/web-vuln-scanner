from backend.utils.helpers import map_cwe


def test_map_cwe_uses_detector_defaults():
    sqli = map_cwe("sqli")
    assert sqli["cwe_id"] == "CWE-89"
    xss = map_cwe("xss")
    assert xss["cwe_id"] == "CWE-79"
