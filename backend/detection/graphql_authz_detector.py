"""GraphQL Authorization Detector — Schema introspection and auth boundary testing.

CWE-285 · OWASP API1:2023
"""
from __future__ import annotations
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding
import json

_INTROSPECTION_QUERY = '{"query":"{ __schema { types { name fields { name } } } }"}'
_DEPTH_QUERY_TEMPLATE = '{"query":"{ __typename %s }"}'
_BATCH_QUERY = '[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]'


class GraphQLAuthzDetector(BaseDetector):
    name = "graphql_authz"

    async def detect(self, target_url: str, site_map: dict[str, object], request_handler: RequestHandler) -> list[Finding]:
        analyzer = ResponseAnalyzer()
        findings: list[Finding] = []
        gql_endpoints = self._find_graphql_endpoints(site_map)

        for url in gql_endpoints[:3]:
            # Test 1: Introspection without auth
            f1 = await self._probe_introspection(request_handler, analyzer, url)
            if f1:
                findings.append(f1)

            # Test 2: Query depth/complexity
            f2 = await self._probe_depth(request_handler, analyzer, url)
            if f2:
                findings.append(f2)

            # Test 3: Batching abuse
            f3 = await self._probe_batching(request_handler, analyzer, url)
            if f3:
                findings.append(f3)

            # Test 4: Introspection without auth (unauthed handler)
            f4 = await self._probe_unauthed_introspection(analyzer, url)
            if f4:
                findings.append(f4)

        return self._dedupe(findings)

    async def _probe_introspection(self, rh, analyzer, url):
        try:
            response = await rh.post_json(url, json.loads(_INTROSPECTION_QUERY))
        except Exception:
            return None
        body = response.text.lower()
        if response.status_code == 200 and "__schema" in body and "types" in body:
            # Count exposed types
            try:
                data = json.loads(response.text)
                type_count = len(data.get("data", {}).get("__schema", {}).get("types", []))
            except Exception:
                type_count = 0
            v = analyzer.classify_confidence(error_signature=True, anomaly_score=0.6)
            return Finding(
                detector=self.name, severity="medium", url=url,
                evidence=f"GraphQL introspection enabled, exposing {type_count} types. Full schema metadata accessible.",
                recommendation="Disable introspection in production. Use schema allowlisting and field-level authorization.",
                confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                validation_signals=list(v["signals"]), parameter=None, payload="introspection",
                method="post", category="graphql-introspection",
                baseline_status=200, mutated_status=response.status_code,
                baseline_length=0, mutated_length=len(response.text),
                request_snapshot=f"POST {url} (introspection query)",
                response_snapshot=analyzer.snapshot_response(response),
                reason="Introspection query returned full schema.", validation_state=str(v["validation_state"]),
            )
        return None

    async def _probe_depth(self, rh, analyzer, url):
        # Build deeply nested query
        nested = "{ __typename " * 12 + "}" * 12
        query = {"query": nested}
        try:
            response = await rh.post_json(url, query)
        except Exception:
            return None
        if response.status_code == 200 and "error" not in response.text.lower():
            v = analyzer.classify_confidence(boolean_delta=True, anomaly_score=0.5)
            return Finding(
                detector=self.name, severity="medium", url=url,
                evidence="GraphQL endpoint accepted deeply nested query (12 levels) without depth limiting.",
                recommendation="Implement query depth limiting (max 5-7 levels) and complexity analysis to prevent DoS.",
                confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                validation_signals=list(v["signals"]), parameter=None, payload="depth-12",
                method="post", category="graphql-depth",
                baseline_status=200, mutated_status=response.status_code,
                baseline_length=0, mutated_length=len(response.text),
                request_snapshot=f"POST {url} (depth-12 query)",
                response_snapshot=analyzer.snapshot_response(response),
                reason="No query depth limit enforced.", validation_state=str(v["validation_state"]),
            )
        return None

    async def _probe_batching(self, rh, analyzer, url):
        try:
            batch = json.loads(_BATCH_QUERY)
            response = await rh.post_json(url, batch)
        except Exception:
            return None
        if response.status_code == 200:
            try:
                data = json.loads(response.text)
                if isinstance(data, list) and len(data) >= 5:
                    v = analyzer.classify_confidence(boolean_delta=True, anomaly_score=0.4)
                    return Finding(
                        detector=self.name, severity="low", url=url,
                        evidence=f"GraphQL batching accepted {len(data)} operations in single request.",
                        recommendation="Limit batch query count to prevent abuse. Implement per-operation rate limiting.",
                        confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                        validation_signals=list(v["signals"]), parameter=None, payload="batch-5",
                        method="post", category="graphql-batching",
                        baseline_status=200, mutated_status=response.status_code,
                        baseline_length=0, mutated_length=len(response.text),
                        request_snapshot=f"POST {url} (batch of 5)",
                        response_snapshot=analyzer.snapshot_response(response),
                        reason="Batch queries accepted without limits.", validation_state=str(v["validation_state"]),
                    )
            except Exception:
                pass
        return None

    async def _probe_unauthed_introspection(self, analyzer, url):
        from backend.core.request_handler import RequestHandler as RH
        try:
            rh = RH(auth={})
            response = await rh.post_json(url, json.loads(_INTROSPECTION_QUERY))
            await rh.close()
        except Exception:
            return None
        body = response.text.lower()
        if response.status_code == 200 and "__schema" in body:
            v = analyzer.classify_confidence(error_signature=True, boolean_delta=True, anomaly_score=0.75)
            return Finding(
                detector=self.name, severity="high", url=url,
                evidence="GraphQL introspection accessible without authentication. Full schema exposed to unauthenticated users.",
                recommendation="Require authentication for introspection. Disable introspection entirely in production.",
                confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                validation_signals=list(v["signals"]), parameter=None, payload="unauthed-introspection",
                method="post", category="graphql-unauthed-introspection",
                baseline_status=200, mutated_status=response.status_code,
                baseline_length=0, mutated_length=len(response.text),
                request_snapshot=f"POST {url} (introspection, no auth)",
                response_snapshot=analyzer.snapshot_response(response),
                reason="Introspection query succeeded without auth.", validation_state=str(v["validation_state"]),
            )
        return None

    @staticmethod
    def _find_graphql_endpoints(site_map):
        urls = set()
        for endpoint in site_map.get("endpoints", []):
            if not isinstance(endpoint, dict):
                continue
            url = str(endpoint.get("url", ""))
            if "graphql" in url.lower() or str(endpoint.get("type", "")) == "graphql":
                urls.add(url)
        for form in site_map.get("forms", []):
            if isinstance(form, dict) and "graphql" in str(form.get("action", "")).lower():
                urls.add(str(form["action"]))
        return list(urls)

    @staticmethod
    def _dedupe(findings):
        seen, out = set(), []
        for f in findings:
            k = (f.url, f.category)
            if k not in seen:
                seen.add(k)
                out.append(f)
        return out
