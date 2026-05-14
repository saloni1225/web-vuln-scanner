from backend.detection.sqli_detector import SQLiDetector
from backend.detection.xss_detector import XSSDetector


def test_sqli_skips_login_route_without_authenticated_profile():
    assert SQLiDetector._should_skip_for_profile(
        "http://127.0.0.1:3000/login?email=baseline",
        {"enable_login_route_probing": False},
    ) is True


def test_sqli_allows_login_route_for_authenticated_profile():
    assert SQLiDetector._should_skip_for_profile(
        "http://127.0.0.1:3000/login?email=baseline",
        {"allow_auth_endpoint_fuzz": True},
    ) is False


def test_xss_skips_login_route_without_authenticated_profile():
    assert XSSDetector._should_skip_for_profile(
        "http://127.0.0.1:3000/rest/saveLoginIp?email=baseline",
        {"enable_login_route_probing": False},
    ) is True


def test_xss_allows_login_route_for_authenticated_profile():
    assert XSSDetector._should_skip_for_profile(
        "http://127.0.0.1:3000/rest/saveLoginIp?email=baseline",
        {"allow_auth_endpoint_fuzz": True},
    ) is False
