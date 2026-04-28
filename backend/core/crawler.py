import re
from collections import deque
from html.parser import HTMLParser
import json
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from backend.config.settings import settings
from backend.core.request_handler import RequestHandler


ROUTE_PATTERN = re.compile(r'(?:"|\')((?:/|#)[A-Za-z0-9_?&=./:%+#-]{2,})(?:"|\')')
API_HINT_PATTERN = re.compile(r'(?:"|\')((?:/|https?://)[A-Za-z0-9_?&=./:%+#-]*(?:api|rest|graphql)[A-Za-z0-9_?&=./:%+#-]*)(?:"|\')', re.IGNORECASE)
FETCH_PATTERN = re.compile(r'(?:fetch|axios\.(?:get|post|put|patch|delete)|open)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
COMMON_ENDPOINT_CANDIDATES = [
    {"path": "/api"},
    {"path": "/rest"},
    {"path": "/api/Products"},
    {"path": "/rest/products"},
    {"path": "/rest/products/search?q=apple", "query_params": ["q"]},
    {"path": "/rest/user/login", "method": "post", "inputs": ["email", "password"]},
    {"path": "/graphql", "method": "post", "inputs": ["query", "variables"], "type": "graphql"},
    {"path": "/api/graphql", "method": "post", "inputs": ["query", "variables"], "type": "graphql"},
]


def canonicalize_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.fragment.startswith("/"):
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, parsed.fragment))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


def extract_candidates_from_text(text: str) -> list[str]:
    candidates: set[str] = set()
    for match in ROUTE_PATTERN.findall(text):
        if match.startswith("//"):
            continue
        candidates.add(match)
    return sorted(candidates)


def extract_hidden_api_candidates(text: str) -> list[str]:
    candidates: set[str] = set()
    for pattern in (API_HINT_PATTERN, FETCH_PATTERN):
        for match in pattern.findall(text):
            if isinstance(match, tuple):
                match = match[0]
            if match.startswith("//"):
                continue
            candidates.add(str(match))
    return sorted(candidates)


def guess_query_params(url: str) -> list[str]:
    lowered = url.lower()
    guessed: set[str] = set()
    if "search" in lowered:
        guessed.add("q")
    if "login" in lowered:
        guessed.update({"email", "password"})
    if "user" in lowered and "id" in lowered:
        guessed.add("id")
    return sorted(guessed)


def classify_endpoint_type(url: str) -> str:
    lowered = url.lower()
    if "graphql" in lowered:
        return "graphql"
    if any(token in lowered for token in ("/api", "/rest", ".json")):
        return "api"
    return "page"


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()
        self.script_sources: set[str] = set()
        self.forms: list[dict[str, object]] = []
        self._current_form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key: value or "" for key, value in attrs}
        if tag == "a" and attr_map.get("href"):
            self.links.add(attr_map["href"])
        if tag == "script" and attr_map.get("src"):
            self.script_sources.add(attr_map["src"])
        if tag == "form":
            self._current_form = {
                "action": attr_map.get("action", ""),
                "method": attr_map.get("method", "get").lower(),
                "inputs": [],
            }
        if tag in {"input", "textarea", "select"} and self._current_form is not None:
            inputs = self._current_form["inputs"]
            assert isinstance(inputs, list)
            inputs.append(attr_map.get("name", ""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class Crawler:
    def __init__(self, request_handler: RequestHandler, scan_options: dict[str, object] | None = None) -> None:
        self.request_handler = request_handler
        self.scan_options = scan_options or {}

    async def crawl(self, start_url: str) -> dict[str, object]:
        parsed_start = urlparse(start_url)
        queue: deque[tuple[str, int]] = deque([(canonicalize_url(start_url), 0)])
        seen: set[str] = set()
        pages: list[str] = []
        page_details: list[dict[str, object]] = []
        forms: list[dict[str, object]] = []
        endpoints: list[dict[str, object]] = []
        script_sources: set[str] = set()

        await self._crawl_queue(queue, seen, parsed_start, pages, page_details, forms, endpoints, script_sources)

        await self._expand_from_scripts(script_sources, parsed_start, queue, endpoints)
        await self._crawl_queue(queue, seen, parsed_start, pages, page_details, forms, endpoints, script_sources)
        await self._probe_common_endpoints(start_url, parsed_start, endpoints, forms)
        await self._crawl_dynamic(start_url, parsed_start, pages, page_details, forms, endpoints)
        await self._discover_api_shapes(endpoints, forms)
        if self.scan_options.get("enable_openapi_discovery", settings.enable_openapi_discovery):
            await self._discover_openapi_spec(start_url, parsed_start, endpoints, forms)
            await self._enumerate_id_patterns(endpoints)
        api_summary = self._summarize_api_surface(endpoints)

        return {
            "pages": self._dedupe_strings(pages),
            "page_details": self._dedupe_dicts(page_details, "url"),
            "forms": self._dedupe_forms(forms),
            "endpoints": self._dedupe_endpoints(endpoints),
            "api_summary": api_summary,
        }

    async def _crawl_queue(
        self,
        queue: deque[tuple[str, int]],
        seen: set[str],
        parsed_start,
        pages: list[str],
        page_details: list[dict[str, object]],
        forms: list[dict[str, object]],
        endpoints: list[dict[str, object]],
        script_sources: set[str],
    ) -> None:
        while queue and len(pages) < settings.max_pages:
            url, depth = queue.popleft()
            clean_url = canonicalize_url(url)
            if clean_url in seen or depth > settings.max_depth:
                continue

            seen.add(clean_url)
            try:
                response = await self.request_handler.get(clean_url)
            except Exception:
                continue

            self._register_page(response.url, depth, response.status_code, pages, page_details, endpoints)
            parser = LinkParser()
            parser.feed(response.text)
            script_sources.update({urljoin(response.url, script) for script in parser.script_sources})

            for form in parser.forms:
                self._register_form(response.url, form, forms, endpoints)

            for href in parser.links:
                next_url = canonicalize_url(urljoin(response.url, href))
                if self._same_origin(next_url, parsed_start):
                    queue.append((next_url, depth + 1))

            for candidate in extract_candidates_from_text(response.text):
                next_url = canonicalize_url(urljoin(response.url, candidate))
                if self._same_origin(next_url, parsed_start):
                    queue.append((next_url, depth + 1))
                    self._register_endpoint(next_url, "get", "bundle-candidate", endpoints, guess_query_params(next_url))
            for api_candidate in extract_hidden_api_candidates(response.text):
                next_url = canonicalize_url(urljoin(response.url, api_candidate))
                if self._same_origin(next_url, parsed_start):
                    self._register_endpoint(
                        next_url,
                        "get",
                        "hidden-api",
                        endpoints,
                        guess_query_params(next_url),
                        endpoint_type=classify_endpoint_type(next_url),
                    )

    async def _expand_from_scripts(
        self,
        script_sources: set[str],
        parsed_start,
        queue: deque[tuple[str, int]],
        endpoints: list[dict[str, object]],
    ) -> None:
        for script_url in list(script_sources)[: settings.max_script_bundles]:
            if not self._same_origin(script_url, parsed_start):
                continue
            try:
                response = await self.request_handler.get(script_url)
            except Exception:
                continue
            for candidate in extract_candidates_from_text(response.text):
                candidate_url = canonicalize_url(urljoin(script_url, candidate))
                if not self._same_origin(candidate_url, parsed_start):
                    continue
                queue.append((candidate_url, 1))
                self._register_endpoint(candidate_url, "get", "script-analysis", endpoints, guess_query_params(candidate_url))
            for api_candidate in extract_hidden_api_candidates(response.text):
                candidate_url = canonicalize_url(urljoin(script_url, api_candidate))
                if not self._same_origin(candidate_url, parsed_start):
                    continue
                self._register_endpoint(
                    candidate_url,
                    "get",
                    "script-hidden-api",
                    endpoints,
                    guess_query_params(candidate_url),
                    endpoint_type=classify_endpoint_type(candidate_url),
                )

    async def _probe_common_endpoints(
        self,
        start_url: str,
        parsed_start,
        endpoints: list[dict[str, object]],
        forms: list[dict[str, object]],
    ) -> None:
        for candidate in COMMON_ENDPOINT_CANDIDATES:
            candidate_url = canonicalize_url(urljoin(start_url, candidate["path"]))
            if not self._same_origin(candidate_url, parsed_start):
                continue
            method = str(candidate.get("method", "get")).lower()
            try:
                if method == "get":
                    response = await self.request_handler.get(candidate_url)
                else:
                    response = await self.request_handler.options(candidate_url)
            except Exception:
                continue
            if response.status_code >= 500:
                continue
            query_params = list(candidate.get("query_params", [])) or guess_query_params(candidate_url)
            self._register_endpoint(
                candidate_url,
                method,
                "common-probe",
                endpoints,
                query_params,
                response.status_code,
                endpoint_type=str(candidate.get("type") or classify_endpoint_type(candidate_url)),
                content_type=response.headers.get("content-type"),
            )
            if method == "post":
                forms.append(
                    {
                        "action": candidate_url,
                        "method": "post",
                        "inputs": list(candidate.get("inputs", [])),
                        "page": start_url,
                        "content_type": "json" if candidate.get("type") == "graphql" else "form",
                    }
                )

    async def _crawl_dynamic(
        self,
        start_url: str,
        parsed_start,
        pages: list[str],
        page_details: list[dict[str, object]],
        forms: list[dict[str, object]],
        endpoints: list[dict[str, object]],
    ) -> None:
        if not settings.enable_playwright_crawl:
            return
        try:
            from playwright.async_api import TimeoutError as PlaywrightTimeoutError
            from playwright.async_api import async_playwright
        except Exception:
            return

        network_requests: set[str] = set()

        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=True)
                context = await browser.new_context(user_agent=settings.user_agent)
                page = await context.new_page()
                page.on("request", lambda request: network_requests.add(request.url))

                try:
                    await page.goto(start_url, wait_until="networkidle", timeout=settings.playwright_timeout_ms)
                    await page.wait_for_timeout(settings.playwright_render_wait_ms)
                except PlaywrightTimeoutError:
                    pass

                current_url = canonicalize_url(page.url)
                self._register_page(current_url, 0, 200, pages, page_details, endpoints, source="playwright")

                hrefs = await page.eval_on_selector_all(
                    "[href]",
                    """
                    (elements) => elements
                      .map((element) => element.getAttribute('href'))
                      .filter(Boolean)
                    """,
                )
                router_links = await page.eval_on_selector_all(
                    "[routerlink]",
                    """
                    (elements) => elements
                      .map((element) => element.getAttribute('routerlink'))
                      .filter(Boolean)
                    """,
                )
                dom_forms = await page.eval_on_selector_all(
                    "form",
                    """
                    (forms) => forms.map((form) => ({
                      action: form.getAttribute('action') || window.location.href,
                      method: (form.getAttribute('method') || 'get').toLowerCase(),
                      inputs: Array.from(form.querySelectorAll('input[name], textarea[name], select[name]'))
                        .map((input) => input.getAttribute('name'))
                        .filter(Boolean),
                    }))
                    """,
                )

                for href in [*hrefs, *router_links]:
                    next_url = canonicalize_url(urljoin(page.url, href))
                    if self._same_origin(next_url, parsed_start):
                        self._register_page(next_url, 1, 200, pages, page_details, endpoints, source="playwright-dom")

                for form in dom_forms:
                    self._register_form(page.url, form, forms, endpoints, source="playwright-dom")

                for request_url in network_requests:
                    normalized = canonicalize_url(request_url)
                    if self._same_origin(normalized, parsed_start):
                        query_params = [name for name, _ in parse_qsl(urlparse(normalized).query)] or guess_query_params(normalized)
                        self._register_endpoint(
                            normalized,
                            "get",
                            "playwright-network",
                            endpoints,
                            query_params,
                            endpoint_type=classify_endpoint_type(normalized),
                        )

                await context.close()
                await browser.close()
        except Exception:
            return

    async def _discover_api_shapes(self, endpoints: list[dict[str, object]], forms: list[dict[str, object]]) -> None:
        inspected = 0
        for endpoint in endpoints:
            if inspected >= settings.max_api_candidates:
                break
            endpoint_type = str(endpoint.get("type", "page"))
            if endpoint_type not in {"api", "graphql"}:
                continue
            url = str(endpoint.get("url", ""))
            method = str(endpoint.get("method", "get")).lower()
            if not url:
                continue
            inspected += 1
            if endpoint_type == "graphql":
                await self._discover_graphql_shape(url, endpoint, forms)
                continue
            if method != "get":
                continue
            try:
                response = await self.request_handler.get(url)
            except Exception:
                continue
            body = response.text.strip()
            content_type = response.headers.get("content-type", "").lower()
            schema_fields: list[str] = []
            if "json" in content_type or body.startswith("{") or body.startswith("["):
                try:
                    payload = json.loads(body)
                except json.JSONDecodeError:
                    payload = None
                schema_fields = self._extract_schema_fields(payload)
            if schema_fields:
                endpoint["schema_fields"] = schema_fields
                forms.append(
                    {
                        "action": url,
                        "method": "post",
                        "inputs": schema_fields[:8],
                        "page": url,
                        "source": "schema-discovery",
                        "content_type": "json",
                    }
                )

    async def _discover_graphql_shape(
        self,
        url: str,
        endpoint: dict[str, object],
        forms: list[dict[str, object]],
    ) -> None:
        introspection_query = "{__schema{queryType{name}mutationType{name}types{name kind fields{name args{name type{name kind ofType{name kind}}}}}}}"
        try:
            response = await self.request_handler.post_json(url, {"query": introspection_query, "variables": {}})
        except Exception:
            endpoint["graphql_summary"] = {"introspection_enabled": False, "top_level_keys": []}
            forms.append({"action": url, "method": "post", "inputs": ["query", "variables"], "page": url, "source": "graphql-probe", "content_type": "json"})
            return
        try:
            payload = json.loads(response.text)
        except json.JSONDecodeError:
            payload = {}
        summary = self._summarize_graphql_payload(payload)
        fields = self._extract_graphql_fields(payload)
        endpoint["graphql_summary"] = summary | {"operation_fields": fields[:20]}
        endpoint["schema_fields"] = ["query", "variables", *fields[:8]]
        forms.append(
            {
                "action": url,
                "method": "post",
                "inputs": ["query", "variables", *fields[:8]],
                "page": url,
                "source": "graphql-introspection" if summary.get("introspection_enabled") else "graphql-probe",
                "content_type": "json",
            }
        )

    async def _discover_openapi_spec(self, start_url: str, parsed_start, endpoints: list[dict[str, object]], forms: list[dict[str, object]]) -> None:
        spec_paths = ["/openapi.json", "/swagger.json", "/api-docs", "/v1/api-docs"]
        spec_payload = None
        for path in spec_paths:
            test_url = canonicalize_url(urljoin(start_url, path))
            try:
                response = await self.request_handler.get(test_url)
                if response.status_code == 200 and ("json" in response.headers.get("content-type", "").lower() or response.text.startswith("{")):
                    payload = json.loads(response.text)
                    if "openapi" in payload or "swagger" in payload:
                        spec_payload = payload
                        break
            except Exception:
                continue

        if not spec_payload:
            return

        paths = spec_payload.get("paths", {})
        for path, methods in paths.items():
            base_url = canonicalize_url(urljoin(start_url, path.replace("{", "").replace("}", "")))
            for method_name, details in methods.items():
                method_name = method_name.lower()
                if method_name not in {"get", "post", "put", "delete", "options"}:
                    continue
                parameters = details.get("parameters", [])
                query_params = [p.get("name") for p in parameters if p.get("in") == "query" and p.get("name")]
                body_fields = self._extract_openapi_request_fields(details, spec_payload)
                field_types = self._extract_openapi_request_field_types(details, spec_payload)
                self._register_endpoint(base_url, method_name, "openapi-spec", endpoints, [*query_params, *body_fields], endpoint_type="api")
                if endpoints:
                    endpoints[-1]["schema_field_types"] = field_types
                if method_name in {"post", "put", "patch"}:
                    forms.append({
                        "action": base_url,
                        "method": method_name,
                        "inputs": [*query_params, *body_fields],
                        "page": start_url,
                        "source": "openapi-spec",
                        "content_type": "json"
                    })

    async def _enumerate_id_patterns(self, endpoints: list[dict[str, object]]) -> None:
        # Simple IDOR enumeration: if path ends with /1, add /2, /0, /999
        new_endpoints = []
        for endpoint in endpoints:
            url = endpoint["url"]
            if re.search(r'/[0-9]+$', url):
                for new_id in ["0", "2", "999"]:
                    new_url = re.sub(r'/[0-9]+$', f'/{new_id}', url)
                    new_endpoints.append({
                        **endpoint,
                        "url": new_url,
                        "source": "id-enumeration"
                    })
        endpoints.extend(new_endpoints)

    def _register_page(
        self,
        url: str,
        depth: int,
        status_code: int,
        pages: list[str],
        page_details: list[dict[str, object]],
        endpoints: list[dict[str, object]],
        source: str = "crawler",
    ) -> None:
        normalized = canonicalize_url(url)
        query_params = [name for name, _ in parse_qsl(urlparse(normalized).query)]
        pages.append(normalized)
        page_details.append(
            {
                "url": normalized,
                "depth": depth,
                "status_code": status_code,
                "query_params": query_params,
                "source": source,
            }
        )
        self._register_endpoint(normalized, "get", source, endpoints, query_params, status_code)

    def _register_form(
        self,
        page_url: str,
        form: dict[str, object],
        forms: list[dict[str, object]],
        endpoints: list[dict[str, object]],
        source: str = "crawler",
    ) -> None:
        action = canonicalize_url(urljoin(page_url, str(form.get("action", ""))))
        normalized_inputs = [name for name in form.get("inputs", []) if name]
        form_entry = {
            **form,
            "page": canonicalize_url(page_url),
            "action": action,
            "inputs": normalized_inputs,
            "source": source,
            "content_type": str(form.get("content_type", "form")),
        }
        forms.append(form_entry)
        self._register_endpoint(
            action,
            str(form.get("method", "get")).lower(),
            source,
            endpoints,
            normalized_inputs,
            endpoint_type=classify_endpoint_type(action),
        )

    def _register_endpoint(
        self,
        url: str,
        method: str,
        source: str,
        endpoints: list[dict[str, object]],
        params: list[str] | None = None,
        status_code: int | None = None,
        endpoint_type: str | None = None,
        content_type: str | None = None,
    ) -> None:
        normalized = canonicalize_url(url)
        endpoints.append(
            {
                "type": endpoint_type or classify_endpoint_type(normalized),
                "url": normalized,
                "method": method,
                "source": source,
                "query_params": params or [],
                "schema_fields": [],
                "status_code": status_code,
                "content_type": content_type or "",
            }
        )

    @staticmethod
    def _same_origin(url: str, parsed_start) -> bool:
        return urlparse(url).netloc == parsed_start.netloc

    @staticmethod
    def _dedupe_strings(values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))

    @staticmethod
    def _dedupe_dicts(values: list[dict[str, object]], key: str) -> list[dict[str, object]]:
        deduped: dict[str, dict[str, object]] = {}
        for value in values:
            deduped[str(value[key])] = value
        return list(deduped.values())

    @staticmethod
    def _dedupe_forms(values: list[dict[str, object]]) -> list[dict[str, object]]:
        deduped: dict[tuple[str, str, tuple[str, ...]], dict[str, object]] = {}
        for value in values:
            form_key = (
                str(value.get("action", "")),
                str(value.get("method", "get")).lower(),
                tuple(sorted(str(item) for item in value.get("inputs", []))),
            )
            deduped[form_key] = value
        return list(deduped.values())

    @staticmethod
    def _dedupe_endpoints(values: list[dict[str, object]]) -> list[dict[str, object]]:
        deduped: dict[tuple[str, str], dict[str, object]] = {}
        for value in values:
            endpoint_key = (str(value.get("method", "get")).lower(), str(value.get("url", "")))
            current = deduped.get(endpoint_key)
            if current is None or len(value.get("query_params", [])) > len(current.get("query_params", [])):
                deduped[endpoint_key] = value
        return list(deduped.values())

    @staticmethod
    def _summarize_api_surface(endpoints: list[dict[str, object]]) -> dict[str, object]:
        api_endpoints = [item for item in endpoints if str(item.get("type")) == "api"]
        graphql_endpoints = [item for item in endpoints if str(item.get("type")) == "graphql"]
        methods = sorted({str(item.get("method", "get")).upper() for item in endpoints})
        parameterized = sum(1 for item in endpoints if item.get("query_params"))
        schema_modeled = sum(1 for item in endpoints if item.get("schema_fields"))
        return {
            "api_endpoint_count": len(api_endpoints),
            "graphql_endpoint_count": len(graphql_endpoints),
            "parameterized_endpoint_count": parameterized,
            "schema_modeled_endpoint_count": schema_modeled,
            "methods": methods,
            "top_sources": sorted({str(item.get("source", "crawler")) for item in endpoints}),
            "hidden_endpoint_count": sum(1 for item in endpoints if "hidden" in str(item.get("source", ""))),
        }

    @staticmethod
    def _extract_schema_fields(payload: object) -> list[str]:
        if isinstance(payload, dict):
            keys = [str(key) for key in payload.keys()]
            if "data" in payload and isinstance(payload.get("data"), dict):
                keys.extend(str(key) for key in payload["data"].keys())
            return list(dict.fromkeys(keys))
        if isinstance(payload, list) and payload and isinstance(payload[0], dict):
            return [str(key) for key in payload[0].keys()]
        return []

    @classmethod
    def _extract_openapi_request_fields(cls, operation: dict[str, object], spec: dict[str, object]) -> list[str]:
        request_body = operation.get("requestBody", {})
        if not isinstance(request_body, dict):
            return []
        content = request_body.get("content", {})
        if not isinstance(content, dict):
            return []
        fields: list[str] = []
        for media in content.values():
            if not isinstance(media, dict):
                continue
            schema = media.get("schema", {})
            fields.extend(cls._extract_openapi_schema_fields(schema, spec))
        return list(dict.fromkeys(fields))

    @classmethod
    def _extract_openapi_request_field_types(cls, operation: dict[str, object], spec: dict[str, object]) -> dict[str, str]:
        request_body = operation.get("requestBody", {})
        if not isinstance(request_body, dict):
            return {}
        content = request_body.get("content", {})
        if not isinstance(content, dict):
            return {}
        field_types: dict[str, str] = {}
        for media in content.values():
            if not isinstance(media, dict):
                continue
            schema = media.get("schema", {})
            field_types.update(cls._extract_openapi_schema_field_types(schema, spec))
        return field_types

    @classmethod
    def _extract_openapi_schema_fields(cls, schema: object, spec: dict[str, object]) -> list[str]:
        if not isinstance(schema, dict):
            return []
        if "$ref" in schema:
            resolved = cls._resolve_openapi_ref(str(schema["$ref"]), spec)
            return cls._extract_openapi_schema_fields(resolved, spec)
        fields: list[str] = []
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            fields.extend(str(key) for key in properties.keys())
        for nested_key in ("items", "allOf", "anyOf", "oneOf"):
            nested = schema.get(nested_key)
            if isinstance(nested, dict):
                fields.extend(cls._extract_openapi_schema_fields(nested, spec))
            elif isinstance(nested, list):
                for item in nested:
                    fields.extend(cls._extract_openapi_schema_fields(item, spec))
        return list(dict.fromkeys(fields))

    @classmethod
    def _extract_openapi_schema_field_types(cls, schema: object, spec: dict[str, object]) -> dict[str, str]:
        if not isinstance(schema, dict):
            return {}
        if "$ref" in schema:
            resolved = cls._resolve_openapi_ref(str(schema["$ref"]), spec)
            return cls._extract_openapi_schema_field_types(resolved, spec)
        field_types: dict[str, str] = {}
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for key, value in properties.items():
                if isinstance(value, dict):
                    field_types[str(key)] = str(value.get("type") or value.get("format") or "string")
        for nested_key in ("allOf", "anyOf", "oneOf"):
            nested = schema.get(nested_key)
            if isinstance(nested, list):
                for item in nested:
                    field_types.update(cls._extract_openapi_schema_field_types(item, spec))
        return field_types

    @staticmethod
    def _resolve_openapi_ref(ref: str, spec: dict[str, object]) -> object:
        if not ref.startswith("#/"):
            return {}
        current: object = spec
        for part in ref[2:].split("/"):
            if not isinstance(current, dict):
                return {}
            current = current.get(part, {})
        return current

    @staticmethod
    def _extract_graphql_fields(payload: object) -> list[str]:
        if not isinstance(payload, dict):
            return []
        schema = payload.get("data", {}).get("__schema", {}) if isinstance(payload.get("data"), dict) else {}
        if not isinstance(schema, dict):
            return []
        fields: list[str] = []
        for type_info in schema.get("types", []) or []:
            if not isinstance(type_info, dict) or type_info.get("kind") not in {"OBJECT", "INPUT_OBJECT"}:
                continue
            for field in type_info.get("fields", []) or []:
                if isinstance(field, dict) and field.get("name"):
                    fields.append(str(field["name"]))
                    for arg in field.get("args", []) or []:
                        if isinstance(arg, dict) and arg.get("name"):
                            fields.append(str(arg["name"]))
        return list(dict.fromkeys(fields))

    @staticmethod
    def _summarize_graphql_payload(payload: object) -> dict[str, object]:
        if not isinstance(payload, dict):
            return {"introspection_enabled": False, "top_level_keys": []}
        top_level_keys = [str(key) for key in payload.keys()]
        introspection_enabled = "__schema" in json.dumps(payload)
        return {
            "introspection_enabled": introspection_enabled,
            "top_level_keys": top_level_keys,
        }
