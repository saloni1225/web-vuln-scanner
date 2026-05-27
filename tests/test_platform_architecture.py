from backend.api_security.engine import analyze_api_surface
from backend.attack_surface.inventory import build_attack_surface_inventory
from backend.platform import build_platform_overview
from backend.recon.intelligence import build_reconnaissance_matrix
from backend.risk.ai_risk import build_ai_risk_summary
from backend.validation.engine import build_validation_summary


def test_platform_overview_exposes_enterprise_layers():
    overview = build_platform_overview(
        [
            {
                "target_url": "https://example.com",
                "findings_count": 2,
                "high_severity_count": 1,
                "endpoint_count": 4,
                "risk_gate_status": "failed",
            }
        ]
    )

    assert overview["product"] == "AdaptiveScan"
    assert overview["architecture"]["queue"]["broker"] == "redis"
    assert overview["architecture"]["workers"]["worker_pools"]
    assert overview["metrics"]["risk_gate_failures"] == 1
    assert "authorization confirmation" in overview["security"]["controls"]


def test_scan_intelligence_summaries_are_deterministic():
    site_map = {
        "pages": ["https://example.com"],
        "forms": [{"action": "/login"}],
        "endpoints": [
            {"url": "https://example.com/api/users", "type": "api"},
            {"url": "https://example.com/graphql", "type": "graphql"},
            {"url": "https://example.com/admin", "type": "page"},
        ],
    }
    recon = {"dns": {"a_records": ["203.0.113.10"]}, "tls": {"issuer": "test"}}
    finding = {
        "detector": "sqli",
        "url": "https://example.com/api/users",
        "parameter": "id",
        "payload": "'",
        "severity": "high",
        "confidence": "high",
        "validation_state": "validated",
    }
    scan = {
        "scan_id": "scan-1",
        "target_url": "https://example.com",
        "finished_at": "2026-05-28T00:00:00Z",
        "endpoints": site_map["endpoints"],
        "findings": [finding],
    }

    matrix = build_reconnaissance_matrix("https://example.com", site_map, recon)
    api = analyze_api_surface(site_map, {"probe_count": 3})
    validation = build_validation_summary([finding])
    inventory = build_attack_surface_inventory(scan)
    ai = build_ai_risk_summary([finding], inventory)

    assert "graphql" in matrix["exposure_tags"]
    assert api["graphql_endpoint_count"] == 1
    assert validation["validated_count"] == 1
    assert inventory["high_risk_asset_count"] >= 1
    assert ai["high_exploitability_count"] == 1
