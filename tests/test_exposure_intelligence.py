from fastapi.testclient import TestClient

from backend.api_security.schema import analyze_graphql_schema, parse_openapi_document, parse_postman_collection
from backend.app import app
from backend.exposure.intelligence import aggregate_exposure, build_exposure_intelligence


def _scan():
    return {
        "scan_id": "scan-1",
        "target_url": "https://example.com",
        "summary": {"endpoint_count": 12, "high_risk_endpoint_count": 3},
        "endpoints": [
            {"url": "https://example.com/api/users/1", "type": "api", "method": "GET"},
            {"url": "https://example.com/admin", "type": "page", "method": "GET"},
            {"url": "https://example.com/graphql", "type": "graphql", "method": "POST"},
            {"url": "https://example.com/oauth/token", "type": "api", "method": "POST"},
        ],
        "findings": [
            {"detector": "auth_bypass", "severity": "high", "validation_state": "validated", "url": "https://example.com/api/users/1"}
        ],
        "api_security_summary": {"undocumented_endpoint_count": 3, "graphql_endpoint_count": 1},
        "auth_intelligence": {"auth_endpoint_count": 2, "risk_indicators": ["object-authorization-risk"]},
        "attack_surface_graph": {"attack_paths": [{"name": "exposed-api-auth-boundary"}]},
        "recon_summary": {
            "port_summary": {"open_ports": [{"port": 443}]},
            "cloud_asset_summary": {"candidate_count": 12, "exposed_count": 1, "exposed": [{"provider": "aws-s3"}]},
        },
    }


def test_exposure_intelligence_scores_public_api_auth_cloud_risk():
    exposure = build_exposure_intelligence(_scan())

    assert exposure["score"] >= 60
    assert exposure["dimensions"]["api_sensitivity"] >= 50
    assert exposure["dimensions"]["auth_exposure"] >= 40
    assert exposure["priority_assets"][0]["score"] >= exposure["priority_assets"][-1]["score"]
    assert "run API auth boundary and BOLA checks" in exposure["recommended_operations"]


def test_aggregate_exposure_returns_highest_risk_target():
    low = _scan()
    low["scan_id"] = "scan-low"
    low["endpoints"] = []
    low["findings"] = []
    low["summary"] = {"endpoint_count": 0, "high_risk_endpoint_count": 0}

    aggregate = aggregate_exposure([low, _scan()])

    assert aggregate["highest_risk"]["target_url"] == "https://example.com"
    assert aggregate["score"] > 0


def test_api_schema_parsers_extract_sensitive_operations():
    openapi = parse_openapi_document(
        {
            "info": {"title": "Example API"},
            "security": [{"bearerAuth": []}],
            "paths": {
                "/api/users/{id}": {"get": {"operationId": "getUser"}},
                "/api/admin/delete": {"delete": {"operationId": "deleteAdmin"}},
            },
        }
    )
    postman = parse_postman_collection(
        {
            "info": {"name": "Bug bounty API"},
            "item": [{"name": "Token", "request": {"method": "POST", "url": {"raw": "https://example.com/oauth/token"}}}],
        }
    )
    graphql = analyze_graphql_schema("type Query { user(id: ID): User }\ntype Mutation { updatePayment(id: ID): Payment deleteUser(id: ID): Boolean }")

    assert openapi["endpoint_count"] == 2
    assert openapi["sensitive_endpoint_count"] >= 1
    assert postman["sensitive_endpoint_count"] == 1
    assert graphql["mutation_count"] >= 1
    assert graphql["sensitive_field_count"] >= 1


def test_exposure_and_schema_routes_are_registered():
    client = TestClient(app)
    exposure = client.get("/api/exposure/overview")
    graphql = client.post(
        "/api/api-intelligence/analyze-schema",
        json={"format": "graphql", "schema_text": "type Query { user(id: ID): User }"},
    )

    assert exposure.status_code == 200
    assert "score" in exposure.json()
    assert graphql.status_code == 200
    assert graphql.json()["format"] == "graphql"

