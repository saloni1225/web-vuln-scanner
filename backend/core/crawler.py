import re
from collections import deque
from html.parser import HTMLParser
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
    def __init__(self, request_handler: RequestHandler) -> None:
        self.request_handler = request_handler

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
        return {
            "api_endpoint_count": len(api_endpoints),
            "graphql_endpoint_count": len(graphql_endpoints),
            "parameterized_endpoint_count": parameterized,
            "methods": methods,
            "top_sources": sorted({str(item.get("source", "crawler")) for item in endpoints}),
            "hidden_endpoint_count": sum(1 for item in endpoints if "hidden" in str(item.get("source", ""))),
        }
