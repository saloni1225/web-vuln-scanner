from backend.api_security.engine import analyze_api_surface
from backend.attack_surface.graph import build_attack_surface_graph, build_drift_timeline, correlate_attack_paths
from backend.auth.intelligence import build_auth_intelligence
from backend.recon.javascript import analyze_javascript_intelligence
from tests.auth_helpers import admin_client as client


def _scan(scan_id="scan-1"):
    return {
        "scan_id": scan_id,
        "target_url": "https://example.com",
        "finished_at": "2026-05-28T00:00:00Z",
        "summary": {"high_severity_count": 1, "high_risk_endpoint_count": 2},
        "endpoints": [
            {"url": "https://example.com/api/users/1", "type": "api", "method": "GET"},
            {"url": "https://example.com/graphql", "type": "graphql", "method": "POST"},
            {"url": "https://example.com/admin", "type": "page", "method": "GET"},
            {"url": "https://example.com/login", "type": "page", "method": "GET"},
        ],
        "findings": [
            {
                "detector": "auth_bypass",
                "category": "access-control",
                "url": "https://example.com/api/users/1",
                "parameter": "id",
                "severity": "high",
                "confidence": "high",
                "validation_state": "validated",
            }
        ],
        "recon_summary": {
            "port_summary": {"open_ports": [{"port": 443, "service_hint": "https"}]},
            "cloud_asset_summary": {"exposed": []},
            "subdomain_summary": {"resolved": [{"host": "api.example.com", "addresses": ["203.0.113.10"]}]},
        },
    }


def test_attack_surface_graph_correlates_exposed_api_auth_path():
    scan = _scan()
    graph = build_attack_surface_graph(scan)
    paths = correlate_attack_paths(scan, graph)

    assert graph["node_count"] >= 6
    assert graph["edge_count"] >= 5
    assert paths[0]["name"] == "exposed-api-auth-boundary"
    assert paths[0]["risk_score"] >= 80


def test_drift_timeline_tracks_new_and_removed_exposure():
    older = _scan("scan-old")
    older["endpoints"] = [{"url": "https://example.com/api/users/1", "type": "api"}]
    newer = _scan("scan-new")
    drift = build_drift_timeline([older, newer])

    assert drift["event_count"] == 2
    assert drift["drift_event_count"] >= 1
    assert drift["timeline"][-1]["new_endpoint_count"] >= 1


def test_javascript_and_auth_intelligence_extract_offensive_signals():
    js = analyze_javascript_intelligence(
        "https://example.com",
        [{"url": "https://example.com/app.js", "body": "fetch('/api/internal'); const t='AKIA1234567890ABCDEF'; element.innerHTML=x; //# sourceMappingURL=app.js.map"}],
    )
    auth = build_auth_intelligence(_scan())

    assert "https://example.com/api/internal" in js["internal_endpoints"]
    assert js["secret_findings"]
    assert "innerHTML" in js["dom_sink_indicators"]
    assert auth["auth_endpoint_count"] == 1
    assert "role differential replay" in auth["recommended_tests"]


def test_api_security_scores_undocumented_graphql_surface():
    api = analyze_api_surface(
        {"endpoints": [{"url": "https://example.com/graphql", "type": "graphql"}, {"url": "https://example.com/api/users", "type": "api"}]},
        {"probe_count": 4},
    )

    assert api["graphql_endpoint_count"] == 1
    assert api["undocumented_endpoint_count"] == 2


def test_attack_surface_routes_are_registered():
    assert client.get("/api/attack-surface/graph").status_code == 200
    assert client.get("/api/attack-surface/drift").status_code == 200
    assert client.get("/api/attack-paths").status_code == 200

