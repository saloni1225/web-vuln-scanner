from backend.utils.helpers import build_target_advisory


def test_external_target_is_marked_as_not_safe_for_demo():
    advisory = build_target_advisory("https://example.com")
    assert advisory["safe_for_demo"] is False
    assert advisory["kind"] == "external"


def test_local_target_is_marked_as_safe_for_demo():
    advisory = build_target_advisory("http://127.0.0.1:3000")
    assert advisory["safe_for_demo"] is True
    assert advisory["kind"] == "local-or-private"
