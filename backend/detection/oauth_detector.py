"""OAuth Misconfiguration Detector — OAuth/OIDC flow validation.

CWE-601/CWE-384 · OWASP A07:2021
"""
from __future__ import annotations
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from backend.core.request_handler import RequestHandler
from backend.core.response_analyzer import ResponseAnalyzer
from backend.detection.base_detector import BaseDetector, Finding

_OAUTH_PATH_HINTS = ("/oauth", "/authorize", "/auth/callback", "/login/callback", "/oidc", "/sso", "/signin")
_REDIRECT_PARAMS = {"redirect_uri", "return_url", "callback", "next", "returnto", "redirect", "continue", "return"}


class OAuthDetector(BaseDetector):
    name = "oauth"

    async def detect(self, target_url: str, site_map: dict[str, object], request_handler: RequestHandler) -> list[Finding]:
        analyzer = ResponseAnalyzer()
        findings: list[Finding] = []
        max_params = int(site_map.get("max_detector_params", 6) or 6)
        tested = 0

        # Find OAuth-related endpoints
        for endpoint in site_map.get("endpoints", []):
            if tested >= max_params:
                break
            if not isinstance(endpoint, dict):
                continue
            url = str(endpoint.get("url", ""))
            lower = url.lower()
            params = [str(p).lower() for p in endpoint.get("query_params", []) or endpoint.get("schema_fields", [])]

            if not any(h in lower for h in _OAUTH_PATH_HINTS) and not (set(params) & _REDIRECT_PARAMS):
                continue
            tested += 1

            # Test 1: Open redirect on redirect_uri
            redirect_params = [p for p in params if p in _REDIRECT_PARAMS]
            for param in redirect_params[:1]:
                f = await self._probe_open_redirect(request_handler, analyzer, url, param)
                if f:
                    findings.append(f)

            # Test 2: Missing state parameter
            if any(h in lower for h in ("/authorize", "/oauth")):
                f2 = await self._probe_missing_state(request_handler, analyzer, url)
                if f2:
                    findings.append(f2)

            # Test 3: Implicit flow (response_type=token)
            if any(h in lower for h in ("/authorize", "/oauth")):
                f3 = await self._probe_implicit_flow(request_handler, analyzer, url)
                if f3:
                    findings.append(f3)

        # Check forms for redirect params
        for form in site_map.get("forms", []):
            if tested >= max_params:
                break
            if not isinstance(form, dict):
                continue
            action = str(form.get("action", ""))
            inputs = [str(i).lower() for i in form.get("inputs", []) if i]
            redirect_inputs = [i for i in inputs if i in _REDIRECT_PARAMS]
            if not redirect_inputs:
                continue
            tested += 1
            for param in redirect_inputs[:1]:
                f = await self._probe_open_redirect(request_handler, analyzer, action, param)
                if f:
                    findings.append(f)

        return self._dedupe(findings)

    async def _probe_open_redirect(self, rh, analyzer, url, param):
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query))
        evil_redirect = "https://evil.example.com/steal"
        qs[param] = evil_redirect
        test_url = urlunparse(parsed._replace(query=urlencode(qs)))

        try:
            response = await rh.get(test_url)
        except Exception:
            return None

        # Check if redirect was followed to evil domain or if evil URL appears in response
        redirected_to_evil = "evil.example.com" in str(response.url).lower()
        reflected = evil_redirect in response.text

        if redirected_to_evil or reflected:
            v = analyzer.classify_confidence(dangerous_reflection=True, anomaly_score=0.7)
            return Finding(
                detector=self.name, severity="high", url=url,
                evidence=f"Open redirect via '{param}': redirected to/reflected '{evil_redirect}'." + (" Actually redirected." if redirected_to_evil else " Reflected in response."),
                recommendation="Validate redirect_uri against a strict allowlist of registered callback URLs. Reject absolute URLs to external domains.",
                confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                validation_signals=list(v["signals"]), parameter=param, payload=evil_redirect,
                method="get", category="oauth-open-redirect", baseline_status=200,
                mutated_status=response.status_code, baseline_length=0, mutated_length=len(response.text),
                request_snapshot=f"GET {test_url}",
                response_snapshot=analyzer.snapshot_response(response),
                reason="Redirect parameter accepted arbitrary external URL.", validation_state=str(v["validation_state"]),
            )
        return None

    async def _probe_missing_state(self, rh, analyzer, url):
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query))
        # Remove state parameter if present
        qs.pop("state", None)
        test_url = urlunparse(parsed._replace(query=urlencode(qs)))

        try:
            response = await rh.get(test_url)
        except Exception:
            return None

        # If the endpoint doesn't reject missing state
        if response.status_code in {200, 302, 301}:
            if "state" not in response.text.lower() or response.status_code == 200:
                v = analyzer.classify_confidence(boolean_delta=True, anomaly_score=0.4)
                return Finding(
                    detector=self.name, severity="medium", url=url,
                    evidence="OAuth authorization endpoint accepts requests without 'state' parameter. Vulnerable to CSRF on OAuth flow.",
                    recommendation="Require and validate a cryptographically random 'state' parameter in all OAuth authorization requests.",
                    confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                    validation_signals=list(v["signals"]), parameter="state", payload="missing",
                    method="get", category="oauth-missing-state", baseline_status=200,
                    mutated_status=response.status_code, baseline_length=0, mutated_length=len(response.text),
                    request_snapshot=f"GET {test_url} (no state param)",
                    response_snapshot=analyzer.snapshot_response(response),
                    reason="Authorization endpoint did not reject missing state.", validation_state=str(v["validation_state"]),
                )
        return None

    async def _probe_implicit_flow(self, rh, analyzer, url):
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query))
        qs["response_type"] = "token"
        test_url = urlunparse(parsed._replace(query=urlencode(qs)))

        try:
            response = await rh.get(test_url)
        except Exception:
            return None

        if response.status_code in {200, 302} and "access_token" in response.text.lower():
            v = analyzer.classify_confidence(boolean_delta=True, anomaly_score=0.6)
            return Finding(
                detector=self.name, severity="medium", url=url,
                evidence="OAuth implicit flow (response_type=token) is accepted. Tokens exposed in URL fragment.",
                recommendation="Disable implicit flow. Use authorization code flow with PKCE instead.",
                confidence=str(v["confidence"]), confidence_score=float(v["confidence_score"]),
                validation_signals=list(v["signals"]), parameter="response_type", payload="token",
                method="get", category="oauth-implicit-flow", baseline_status=200,
                mutated_status=response.status_code, baseline_length=0, mutated_length=len(response.text),
                request_snapshot=f"GET {test_url}",
                response_snapshot=analyzer.snapshot_response(response),
                reason="Implicit flow accepted, tokens in URL.", validation_state=str(v["validation_state"]),
            )
        return None

    @staticmethod
    def _dedupe(findings):
        seen, out = set(), []
        for f in findings:
            k = (f.url, f.category)
            if k not in seen:
                seen.add(k)
                out.append(f)
        return out
