from backend.detection.base_detector import BaseDetector


def test_active_post_policy_skips_state_changing_api_by_default():
    form = {
        "action": "http://127.0.0.1:3000/api/Deliverys",
        "method": "post",
        "inputs": ["name", "price"],
        "content_type": "json",
        "source": "schema-discovery",
    }

    assert BaseDetector.allow_active_post_probe(form, {}) is False


def test_active_post_policy_allows_when_explicitly_enabled():
    form = {
        "action": "http://127.0.0.1:3000/api/Deliverys",
        "method": "post",
        "inputs": ["name", "price"],
        "content_type": "json",
    }

    assert BaseDetector.allow_active_post_probe(form, {"allow_state_changing_fuzz": True}) is True


def test_active_post_policy_allows_graphql_probe():
    form = {
        "action": "http://127.0.0.1:3000/graphql",
        "method": "post",
        "inputs": ["query"],
        "content_type": "json",
    }

    assert BaseDetector.allow_active_post_probe(form, {}) is True


def test_active_post_policy_skips_auth_endpoints_by_default():
    form = {
        "action": "http://127.0.0.1:3000/rest/user/login",
        "method": "post",
        "inputs": ["email", "password"],
        "content_type": "json",
    }

    assert BaseDetector.allow_active_post_probe(form, {"allow_state_changing_fuzz": True}) is False
