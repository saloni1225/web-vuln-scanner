from backend.core.recon import analyze_passive_security
from backend.core.recon import detect_waf
from backend.core.recon import rank_endpoint_risk
from backend.core.scan_profiles import apply_scan_profile
from backend.core.scan_profiles import list_scan_profiles


def test_scan_profiles_are_available_and_apply_defaults():
    profiles = list_scan_profiles()

    assert {profile["name"] for profile in profiles} >= {"quick", "deep", "passive", "api", "stealth", "authenticated"}
    options = apply_scan_profile({"scan_profile": "stealth", "enable_api_fuzzing": None})
    assert options["scan_profile"] == "stealth"
    assert options["enable_api_fuzzing"] is True
    assert options["rate_limit_per_second"] == 0.7


def test_passive_security_scores_missing_headers():
    summary = analyze_passive_security({"server": "ExampleServer"})

    assert summary["score"] < 100
    assert any(item["header"] == "content-security-policy" for item in summary["missing_headers"])
    assert summary["server_disclosure"] == "ExampleServer"


def test_waf_detection_uses_headers():
    waf = detect_waf({"cf-ray": "abc", "server": "cloudflare"})

    assert waf["detected"] is True
    assert waf["matches"][0]["name"] == "Cloudflare"


def test_endpoint_risk_ranking_prioritizes_admin_and_graphql():
    site_map = {
        "pages": ["https://example.test/"],
        "endpoints": [
            {"url": "https://example.test/graphql", "method": "POST", "source": "script"},
            {"url": "https://example.test/products", "method": "GET", "source": "crawler"},
            {"url": "https://example.test/admin/users?id=1", "method": "GET", "source": "crawler"},
        ],
    }

    ranking = rank_endpoint_risk(site_map)

    assert ranking[0]["risk_score"] >= ranking[-1]["risk_score"]
    assert any("admin" in item["url"] or "graphql" in item["url"] for item in ranking[:2])
