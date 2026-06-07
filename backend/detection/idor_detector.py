"""IDOR / BOLA Detector — Active probe-based detection of Broken Object-Level Authorization.

Identifies endpoints with numeric/UUID path segments, replays requests with swapped
identifiers, and compares responses to detect unauthorized access to other users'
resources.  Also tests authorization enforcement by stripping auth headers.

CWE-639 · OWASP API1:2023-Broken Object Level Authorization
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse

from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding


# Patterns that indicate a parameterised resource identifier in the URL path.
_ID_SEGMENT_RE = re.compile(
    r"/(?P<id>\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)",
    re.IGNORECASE,
)

# Path tokens that strongly suggest per-user / per-object resources.
_RESOURCE_PATH_HINTS = (
    "/user", "/users", "/account", "/accounts", "/profile", "/profiles",
    "/order", "/orders", "/invoice", "/invoices", "/ticket", "/tickets",
    "/document", "/documents", "/message", "/messages", "/basket", "/cart",
    "/address", "/payment", "/subscription", "/workspace", "/tenant",
    "/project", "/report", "/file",
)

# Query parameter names that typically hold object identifiers.
_ID_PARAM_NAMES = {"id", "user_id", "account_id", "order_id", "uid", "pid", "doc_id", "item_id", "resource_id"}


class IDORDetector(BaseDetector):
    """Actively tests for IDOR / BOLA by swapping resource identifiers."""

    name = "idor"

    async def detect(
        self,
        target_url: str,
        site_map: dict[str, object],
        request_handler: RequestHandler,
    ) -> list[Finding]:
        analyzer = ResponseAnalyzer()
        findings: list[Finding] = []
        max_params = int(site_map.get("max_detector_params", 6) or 6)
        tested = 0

        # --- Probe endpoints with path-embedded IDs ---
        for endpoint in site_map.get("endpoints", []):
            if tested >= max_params:
                break
            if not isinstance(endpoint, dict):
                continue
            url = str(endpoint.get("url", ""))
            if not self._is_resource_url(url):
                continue
            match = _ID_SEGMENT_RE.search(urlparse(url).path)
            if not match:
                continue
            tested += 1
            original_id = match.group("id")
            swapped_id = self._swap_id(original_id)
            swapped_url = self._replace_path_id(url, original_id, swapped_id)

            probe_findings = await self._probe_idor(
                request_handler, analyzer, url, swapped_url,
                param_name="path_id", original_id=original_id, swapped_id=swapped_id,
            )
            findings.extend(probe_findings)

        # --- Probe endpoints with ID query params ---
        for endpoint in site_map.get("endpoints", []):
            if tested >= max_params:
                break
            if not isinstance(endpoint, dict):
                continue
            url = str(endpoint.get("url", ""))
            params = [str(p).lower() for p in endpoint.get("query_params", []) or endpoint.get("schema_fields", [])]
            id_params = [p for p in params if p in _ID_PARAM_NAMES]
            if not id_params:
                continue
            for param in id_params[:1]:
                if tested >= max_params:
                    break
                tested += 1
                probe_findings = await self._probe_idor_query(
                    request_handler, analyzer, url, param,
                )
                findings.extend(probe_findings)

        # --- Probe via auth stripping on resource endpoints ---
        auth_strip_tested = 0
        for endpoint in site_map.get("endpoints", []):
            if auth_strip_tested >= 3:
                break
            if not isinstance(endpoint, dict):
                continue
            url = str(endpoint.get("url", ""))
            if not self._is_resource_url(url):
                continue
            auth_strip_tested += 1
            finding = await self._probe_auth_stripping(request_handler, analyzer, url)
            if finding:
                findings.append(finding)

        return self._dedupe(findings)

    # ------------------------------------------------------------------
    # Probe strategies
    # ------------------------------------------------------------------

    async def _probe_idor(
        self,
        rh: RequestHandler,
        analyzer: ResponseAnalyzer,
        original_url: str,
        swapped_url: str,
        *,
        param_name: str,
        original_id: str,
        swapped_id: str,
    ) -> list[Finding]:
        """Compare responses between original-ID and swapped-ID requests."""
        findings: list[Finding] = []
        try:
            baseline = await rh.get(original_url)
            mutated = await rh.get(swapped_url)
        except Exception:
            return findings

        # Successful access to a *different* resource → BOLA
        if mutated.status_code == 200 and baseline.status_code == 200:
            if analyzer.has_length_anomaly(baseline, mutated, ratio=0.05):
                # Response differs significantly — different data returned
                validation = analyzer.classify_confidence(
                    boolean_delta=True,
                    anomaly_score=analyzer.anomaly_score(baseline, mutated),
                )
                findings.append(Finding(
                    detector=self.name,
                    severity="high",
                    url=original_url,
                    evidence=(
                        f"Swapping {param_name} from {original_id} to {swapped_id} returned 200 "
                        f"with different content ({len(baseline.text)} vs {len(mutated.text)} bytes). "
                        "Likely broken object-level authorization."
                    ),
                    recommendation=(
                        "Enforce server-side authorization checks on every object access. "
                        "Verify the authenticated user owns or has permission to the requested resource."
                    ),
                    confidence=str(validation["confidence"]),
                    confidence_score=float(validation["confidence_score"]),
                    validation_signals=list(validation["signals"]),
                    parameter=param_name,
                    payload=swapped_id,
                    method="get",
                    category="idor-bola",
                    baseline_status=baseline.status_code,
                    mutated_status=mutated.status_code,
                    baseline_length=len(baseline.text),
                    mutated_length=len(mutated.text),
                    request_snapshot=f"GET {swapped_url}",
                    response_snapshot=analyzer.snapshot_response(mutated),
                    reason="Resource ID swap returned different content with 200 status.",
                    validation_state=str(validation["validation_state"]),
                ))
        return findings

    async def _probe_idor_query(
        self,
        rh: RequestHandler,
        analyzer: ResponseAnalyzer,
        url: str,
        param: str,
    ) -> list[Finding]:
        """Test query-parameter based IDOR."""
        findings: list[Finding] = []
        parsed = urlparse(url)
        from urllib.parse import parse_qsl, urlencode
        qs = dict(parse_qsl(parsed.query))
        original_value = qs.get(param, "1")
        swapped = self._swap_id(original_value)
        qs_original = urlencode({**qs, param: original_value})
        qs_swapped = urlencode({**qs, param: swapped})
        original_url = urlunparse(parsed._replace(query=qs_original))
        swapped_url = urlunparse(parsed._replace(query=qs_swapped))

        try:
            baseline = await rh.get(original_url)
            mutated = await rh.get(swapped_url)
        except Exception:
            return findings

        if mutated.status_code == 200 and baseline.status_code == 200:
            if analyzer.has_length_anomaly(baseline, mutated, ratio=0.05):
                validation = analyzer.classify_confidence(
                    boolean_delta=True,
                    anomaly_score=analyzer.anomaly_score(baseline, mutated),
                )
                findings.append(Finding(
                    detector=self.name,
                    severity="high",
                    url=url,
                    evidence=(
                        f"Query param '{param}' swapped from '{original_value}' to '{swapped}' "
                        f"returned 200 with different content. Possible IDOR."
                    ),
                    recommendation=(
                        "Enforce server-side authorization checks on object access via query params. "
                        "Use indirect references or UUID-to-owner mappings."
                    ),
                    confidence=str(validation["confidence"]),
                    confidence_score=float(validation["confidence_score"]),
                    validation_signals=list(validation["signals"]),
                    parameter=param,
                    payload=swapped,
                    method="get",
                    category="idor-query-param",
                    baseline_status=baseline.status_code,
                    mutated_status=mutated.status_code,
                    baseline_length=len(baseline.text),
                    mutated_length=len(mutated.text),
                    request_snapshot=f"GET {swapped_url}",
                    response_snapshot=analyzer.snapshot_response(mutated),
                    reason="ID-bearing query parameter swap returned different content.",
                    validation_state=str(validation["validation_state"]),
                ))
        return findings

    async def _probe_auth_stripping(
        self,
        rh: RequestHandler,
        analyzer: ResponseAnalyzer,
        url: str,
    ) -> Finding | None:
        """Check if a resource endpoint is accessible without authentication headers."""
        try:
            authed = await rh.get(url)
        except Exception:
            return None

        if authed.status_code != 200:
            return None

        # Build an unauthenticated request handler for comparison
        from backend.core.request_handler import RequestHandler as RH
        try:
            unauthed_rh = RH(auth={})
            unauthed = await unauthed_rh.get(url)
            await unauthed_rh.close()
        except Exception:
            return None

        if unauthed.status_code == 200 and not analyzer.has_length_anomaly(authed, unauthed, ratio=0.15):
            # Same content returned without auth — missing authorization
            validation = analyzer.classify_confidence(
                boolean_delta=True,
                anomaly_score=0.7,
            )
            return Finding(
                detector=self.name,
                severity="high",
                url=url,
                evidence=(
                    f"Resource endpoint returned identical content (HTTP 200) with and without authentication. "
                    f"Authorization enforcement appears missing."
                ),
                recommendation=(
                    "Implement authentication middleware that rejects unauthenticated access to resource endpoints. "
                    "Return 401 or 403 for requests missing valid credentials."
                ),
                confidence=str(validation["confidence"]),
                confidence_score=float(validation["confidence_score"]),
                validation_signals=list(validation["signals"]),
                parameter=None,
                payload="auth-stripped",
                method="get",
                category="missing-authz",
                baseline_status=authed.status_code,
                mutated_status=unauthed.status_code,
                baseline_length=len(authed.text),
                mutated_length=len(unauthed.text),
                request_snapshot=f"GET {url} (no auth headers)",
                response_snapshot=analyzer.snapshot_response(unauthed),
                reason="Endpoint returned same content with auth stripped.",
                validation_state=str(validation["validation_state"]),
            )
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_resource_url(url: str) -> bool:
        lower = url.lower()
        return any(hint in lower for hint in _RESOURCE_PATH_HINTS) or bool(_ID_SEGMENT_RE.search(urlparse(url).path))

    @staticmethod
    def _swap_id(original: str) -> str:
        """Generate an adjacent or different ID for comparison probing."""
        if "-" in original and len(original) >= 32:
            # UUID — flip last hex digit
            last_char = original[-1]
            swapped_char = "a" if last_char != "a" else "b"
            return original[:-1] + swapped_char
        try:
            numeric = int(original)
            return str(numeric + 1) if numeric > 0 else "1"
        except ValueError:
            return original + "1"

    @staticmethod
    def _replace_path_id(url: str, original_id: str, new_id: str) -> str:
        parsed = urlparse(url)
        new_path = parsed.path.replace(f"/{original_id}", f"/{new_id}", 1)
        return urlunparse(parsed._replace(path=new_path))

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str]] = set()
        unique: list[Finding] = []
        for finding in findings:
            key = (finding.url, finding.category)
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique
