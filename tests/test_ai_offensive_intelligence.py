from backend.ai.offensive_intelligence import build_offensive_ai_intelligence
from backend.recon.javascript import analyze_javascript_intelligence


def test_offensive_ai_intelligence_predicts_exploitability_and_clusters():
    scan = {
        "target_url": "https://example.com",
        "summary": {"high_severity_count": 1, "endpoint_count": 2, "finding_count": 2},
        "endpoints": [
            {"url": "https://example.com/api/admin/users", "type": "api"},
            {"url": "https://example.com/graphql", "type": "graphql"},
        ],
        "findings": [
            {"detector": "advanced_auth", "category": "idor", "severity": "high", "url": "https://example.com/api/admin/users", "validation_state": "requires-review"},
            {"detector": "advanced_server", "category": "ssrf", "severity": "high", "url": "https://example.com/api/admin/users", "validation_state": "validated"},
        ],
        "attack_surface_graph": {
            "attack_paths": [{"name": "exposed-api-auth-boundary", "risk_score": 86, "steps": ["internet-facing API", "auth weakness"], "finding_samples": [1]}]
        },
    }
    intelligence = build_offensive_ai_intelligence(scan)

    assert intelligence["runtime"]["hf_ready"] is True
    assert intelligence["exploitability_predictions"][0]["score"] >= 80
    assert intelligence["attack_path_confidence"][0]["confidence"] >= 90
    assert intelligence["sensitive_endpoint_predictions"][0]["prediction"] == "sensitive"
    assert intelligence["finding_deduplication"]["cluster_count"] >= 1


def test_javascript_intelligence_extracts_source_maps_and_auth_boundaries():
    result = analyze_javascript_intelligence(
        "https://example.com",
        [
            {
                "url": "https://example.com/app.js",
                "body": "fetch('/api/internal/users'); const accessToken='x'; if (role === 'admin') {} //# sourceMappingURL=app.js.map",
            }
        ],
    )

    assert "https://example.com/api/internal/users" in result["internal_endpoints"]
    assert result["source_map_candidates"] == ["https://example.com/app.js.map"]
    assert result["client_side_auth_analysis"]["stores_tokens"] is True
    assert result["client_side_auth_analysis"]["role_logic_present"] is True
