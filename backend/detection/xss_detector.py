import html
import uuid
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from backend.config.settings import settings
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding
from backend.payloads.payload_generator import PayloadGenerator


class XSSDetector(BaseDetector):
    name = "xss"
    NOISY_PARAM_NAMES = {"eio", "transport", "sid", "t"}
    NOISY_PATH_HINTS = ("/socket.io", "/redirect")

    @staticmethod
    def _build_candidate_urls(url: str, params: list[str]) -> list[tuple[str, str]]:
        parsed = urlparse(url)
        existing = dict(parse_qsl(parsed.query))
        param_names = list(dict.fromkeys([*existing.keys(), *params]))
        candidates: list[tuple[str, str]] = []
        for param in param_names:
            baseline = {name: existing.get(name, "baseline") for name in param_names}
            candidates.append((param, urlunparse(parsed._replace(query=urlencode(baseline)))))
        return candidates

    @staticmethod
    async def _inspect_dom_xss(url: str, marker: str) -> dict[str, object]:
        try:
            from playwright.async_api import TimeoutError as PlaywrightTimeoutError
            from playwright.async_api import async_playwright
        except Exception:
            return {"rendered": False, "contexts": []}

        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                try:
                    await page.goto(url, wait_until="networkidle", timeout=settings.playwright_timeout_ms)
                    await page.wait_for_timeout(min(1200, settings.playwright_render_wait_ms))
                except PlaywrightTimeoutError:
                    pass
                rendered_html = await page.content()
                dom_contexts: list[str] = []
                if marker in rendered_html:
                    dom_contexts.append("rendered-dom")
                escaped_marker = html.escape(marker, quote=True)
                if escaped_marker in rendered_html and escaped_marker != marker:
                    dom_contexts.append("rendered-encoded")
                attr_hits = await page.locator(f"[data-xss*='{marker}'], [alt*='{marker}'], [value*='{marker}']").count()
                if attr_hits:
                    dom_contexts.append("rendered-attribute")
                script_hits = await page.locator("script").evaluate_all(
                    "(scripts, marker) => scripts.some((script) => (script.textContent || '').includes(marker))",
                    marker,
                )
                if script_hits:
                    dom_contexts.append("rendered-script")
                await context.close()
                await browser.close()
                return {"rendered": bool(dom_contexts), "contexts": list(dict.fromkeys(dom_contexts))}
        except Exception:
            return {"rendered": False, "contexts": []}

    @classmethod
    def _should_probe_param(cls, url: str, param: str) -> bool:
        lowered_url = url.lower()
        return param.lower() not in cls.NOISY_PARAM_NAMES and not any(hint in lowered_url for hint in cls.NOISY_PATH_HINTS)

    @staticmethod
    def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
        deduped: dict[tuple[str, str | None, str | None, str, str | None], Finding] = {}
        for finding in findings:
            key = (finding.detector, finding.parameter, finding.input_location, finding.url, finding.reflection_context)
            current = deduped.get(key)
            if current is None:
                deduped[key] = finding
                continue
            ranking = {"high": 3, "medium": 2, "low": 1}
            if ranking.get(finding.confidence or "low", 1) > ranking.get(current.confidence or "low", 1):
                deduped[key] = finding
        return list(deduped.values())

    @staticmethod
    async def _submit_body(
        request_handler: RequestHandler,
        action: str,
        body: dict[str, str],
        content_type: str,
    ):
        if content_type == "json":
            return await request_handler.post_json(action, body)
        return await request_handler.post(action, body)

    async def detect(
        self,
        target_url: str,
        site_map: dict[str, object],
        request_handler: RequestHandler,
    ) -> list[Finding]:
        analyzer = ResponseAnalyzer()
        findings: list[Finding] = []
        marker = f"awvs-{uuid.uuid4().hex[:8]}"
        payloads = PayloadGenerator().xss_probe_payloads(marker)

        get_candidates: list[tuple[str, str]] = []
        for page in site_map.get("pages", []):
            parsed = urlparse(str(page))
            params = list(dict(parse_qsl(parsed.query)).keys())
            get_candidates.extend(self._build_candidate_urls(str(page), params))
        for endpoint in site_map.get("endpoints", []):
            if not isinstance(endpoint, dict) or str(endpoint.get("method", "get")).lower() != "get":
                continue
            params = [str(name) for name in endpoint.get("query_params", []) if name]
            get_candidates.extend(self._build_candidate_urls(str(endpoint.get("url", "")), params))

        seen_get: set[tuple[str, str]] = set()
        for param, baseline_url in get_candidates:
            if not param or (baseline_url, param) in seen_get:
                continue
            if not self._should_probe_param(baseline_url, param):
                continue
            seen_get.add((baseline_url, param))
            parsed = urlparse(baseline_url)
            baseline_params = dict(parse_qsl(parsed.query))
            try:
                baseline_response = await request_handler.get(baseline_url)
            except Exception:
                continue
            for payload in payloads:
                test_url = urlunparse(parsed._replace(query=urlencode(baseline_params | {param: payload})))
                try:
                    response = await request_handler.get(test_url)
                except Exception:
                    continue
                reflection = analyzer.classify_reflection_context(response, marker)
                dom_result = await self._inspect_dom_xss(test_url, marker)
                contexts = [*reflection["contexts"], *dom_result["contexts"]]
                if not reflection["reflected"] and not dom_result["rendered"]:
                    continue
                if reflection.get("encoded_only") and not dom_result["rendered"]:
                    continue
                content_type = response.headers.get("content-type", "").lower()
                html_like = "html" in content_type or response.text.lstrip().startswith("<!doctype") or response.text.lstrip().startswith("<html")
                dangerous_context = reflection["dangerous"] or any(
                    context in {"rendered-script", "rendered-attribute", "attribute", "script"} for context in contexts
                )
                stable_html_reflection = (
                    baseline_response.status_code < 400
                    and response.status_code < 400
                    and html_like
                    and any(context in {"dom-text", "rendered-dom"} for context in contexts)
                )
                if not dangerous_context and not stable_html_reflection:
                    continue
                confidence = "high" if dangerous_context else "medium"
                severity = "high" if dangerous_context else "medium"
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=severity,
                        url=test_url,
                        evidence=f"Query parameter {param} reflected the probe marker in {', '.join(contexts) or 'response body'}.",
                        recommendation="Encode untrusted output by context, validate high-risk inputs, and review client-side sinks that write untrusted data into the DOM.",
                        confidence=confidence,
                        parameter=param,
                        payload=payload,
                        method="get",
                        category="query-parameter",
                        baseline_status=baseline_response.status_code,
                        mutated_status=response.status_code,
                        baseline_length=len(baseline_response.text),
                        mutated_length=len(response.text),
                        reason="Marker was reflected in a server or browser-rendered context after parameter injection.",
                        input_location=f"query:{param}",
                        reflection_context=", ".join(contexts) if contexts else None,
                        dom_observation=", ".join(dom_result["contexts"]) if dom_result["contexts"] else None,
                    )
                )
                break

        for form in site_map.get("forms", []):
            if not isinstance(form, dict):
                continue
            action = str(form.get("action", ""))
            method = str(form.get("method", "get")).lower()
            source_page = str(form.get("page", action))
            inputs = [name for name in form.get("inputs", []) if name]
            content_type = str(form.get("content_type", "form")).lower()
            if method != "post" or not action or not inputs:
                continue
            for param in inputs:
                if not self._should_probe_param(action, param):
                    continue
                body = {name: "baseline" for name in inputs}
                try:
                    baseline_response = await self._submit_body(request_handler, action, body, content_type)
                except Exception:
                    continue
                for payload in payloads:
                    mutated_body = {name: "baseline" for name in inputs}
                    mutated_body[param] = payload
                    try:
                        response = await self._submit_body(request_handler, action, mutated_body, content_type)
                    except Exception:
                        continue
                    reflection = analyzer.classify_reflection_context(response, marker)
                    dom_result = await self._inspect_dom_xss(action, marker)
                    persistent_page_reflection = None
                    try:
                        persistent_candidate = await request_handler.get(source_page)
                        persistent_page_reflection = analyzer.classify_reflection_context(persistent_candidate, marker)
                    except Exception:
                        persistent_page_reflection = None

                    contexts = [*reflection["contexts"], *dom_result["contexts"]]
                    if persistent_page_reflection and persistent_page_reflection["reflected"]:
                        contexts.extend([f"persistence-{context}" for context in persistent_page_reflection["contexts"]])
                    if not contexts:
                        continue
                    if reflection.get("encoded_only") and not dom_result["rendered"] and not (
                        persistent_page_reflection and persistent_page_reflection["reflected"]
                    ):
                        continue
                    stored_indicator = bool(
                        persistent_page_reflection and persistent_page_reflection["reflected"] and "encoded" not in persistent_page_reflection["contexts"]
                    )
                    content_type = response.headers.get("content-type", "").lower()
                    html_like = "html" in content_type or response.text.lstrip().startswith("<!doctype") or response.text.lstrip().startswith("<html")
                    dangerous_context = reflection["dangerous"] or any(
                        context in {"rendered-script", "rendered-attribute", "attribute", "script"} for context in contexts
                    )
                    stable_html_reflection = (
                        baseline_response.status_code < 400
                        and response.status_code < 400
                        and html_like
                        and any(context in {"dom-text", "rendered-dom"} for context in contexts)
                    )
                    if not stored_indicator and not dangerous_context and not stable_html_reflection:
                        continue
                    confidence = "high" if dangerous_context else "medium"
                    if stored_indicator:
                        confidence = "high"
                    severity = "high" if dangerous_context or stored_indicator else "medium"
                    findings.append(
                        Finding(
                            detector=self.name,
                            severity=severity,
                            url=action,
                            evidence=(
                                f"POST form field {param} reflected the probe marker in {', '.join(contexts)}."
                                if not stored_indicator
                                else f"POST form field {param} appears to persist the probe marker after submission."
                            ),
                            recommendation="Encode server output by context, sanitize rich text, and review client-side DOM writes for untrusted form input.",
                            confidence=confidence,
                            parameter=param,
                            payload=payload,
                            method="post",
                            category="stored-or-reflected-form-input" if stored_indicator else "form-field",
                            baseline_status=baseline_response.status_code,
                            mutated_status=response.status_code,
                            baseline_length=len(baseline_response.text),
                            mutated_length=len(response.text),
                            reason="Form submission reflected or persisted the probe marker in server or browser-rendered output.",
                            input_location=f"form:{param}",
                            reflection_context=", ".join(dict.fromkeys(contexts)) if contexts else None,
                            dom_observation=", ".join(dom_result["contexts"]) if dom_result["contexts"] else None,
                        )
                    )
                    break

        return self._dedupe_findings(findings)
