from backend.core.crawler import Crawler
from backend.core.schema_fuzzer import run_schema_fuzzing
import pytest


class FakeResponse:
    def __init__(self, text: str = "{}", status_code: int = 200, headers: dict[str, str] | None = None) -> None:
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"content-type": "application/json"}


class FakeHandler:
    async def get(self, url: str):
        return FakeResponse('{"q":"scanner"}')

    async def post_json(self, url: str, body: dict[str, object]):
        if "graphql" in url:
            return FakeResponse('{"data":{"__typename":"Query"}}')
        return FakeResponse('{"email":"scanner@example.test"}')


class ErrorHandler(FakeHandler):
    async def post_json(self, url: str, body: dict[str, object]):
        return FakeResponse("server error", status_code=500)


def test_openapi_request_body_field_extraction():
    spec = {
        "components": {
            "schemas": {
                "Login": {
                    "type": "object",
                    "properties": {"email": {"type": "string"}, "password": {"type": "string"}},
                }
            }
        }
    }
    operation = {
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/Login"}
                }
            }
        }
    }

    fields = Crawler._extract_openapi_request_fields(operation, spec)

    assert fields == ["email", "password"]


def test_openapi_request_body_field_type_extraction():
    spec = {
        "components": {
            "schemas": {
                "Product": {
                    "type": "object",
                    "properties": {"id": {"type": "integer"}, "price": {"type": "number"}},
                }
            }
        }
    }
    operation = {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Product"}}}}}

    field_types = Crawler._extract_openapi_request_field_types(operation, spec)

    assert field_types == {"id": "integer", "price": "number"}


@pytest.mark.anyio
async def test_schema_fuzzer_records_rest_and_graphql_probes():
    site_map = {
        "endpoints": [
            {"type": "api", "url": "https://example.test/api/search", "method": "get", "query_params": ["q"], "schema_fields": []},
            {"type": "graphql", "url": "https://example.test/graphql", "method": "post", "query_params": [], "schema_fields": ["query"]},
        ]
    }

    summary = await run_schema_fuzzing(site_map, FakeHandler())

    assert summary["probe_count"] == 2
    assert summary["mutation_case_count"] >= 2
    assert summary["probes"][0]["reflected_fields"] == ["q"]
    assert summary["graphql"][0]["data_keys"] == ["__typename"]


@pytest.mark.anyio
async def test_schema_fuzzer_skips_state_changing_juice_shop_style_endpoints():
    site_map = {
        "endpoints": [
            {"type": "api", "url": "https://example.test/api/Deliverys", "method": "post", "query_params": [], "schema_fields": ["name"]},
            {"type": "api", "url": "https://example.test/api/Hints", "method": "post", "query_params": [], "schema_fields": ["text"]},
        ]
    }

    summary = await run_schema_fuzzing(site_map, FakeHandler(), allow_state_changing=False)

    assert summary["probe_count"] == 0
    assert summary["skipped_count"] == 2


@pytest.mark.anyio
async def test_schema_fuzzer_stops_after_one_server_error_probe():
    site_map = {
        "endpoints": [
            {"type": "api", "url": "https://example.test/api/custom", "method": "post", "query_params": [], "schema_fields": ["name"]},
        ]
    }

    summary = await run_schema_fuzzing(site_map, ErrorHandler(), allow_state_changing=True)

    assert summary["probes"][0]["status"] == "skipped"
    assert "HTTP 500" in summary["probes"][0]["reason"]
