from backend.core.request_handler import RequestHandler
from backend.detection.base_detector import BaseDetector, Finding


class AuthBypassDetector(BaseDetector):
    name = "auth_bypass"
    PRIVILEGED_API_HINTS = ("/rest/admin", "/api/users", "/rest/user", "/api/basket", "/rest/basket")
    KNOWN_SAFE_PUBLIC_ENDPOINTS = ("/rest/user/whoami",)

    async def detect(
        self,
        target_url: str,
        site_map: dict[str, object],
        request_handler: RequestHandler,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for endpoint in site_map.get("endpoints", []):
            if not isinstance(endpoint, dict):
                continue
            url = str(endpoint.get("url", ""))
            lowered_url = url.lower()
            if not any(hint in lowered_url for hint in self.PRIVILEGED_API_HINTS):
                continue
            if any(public_hint in lowered_url for public_hint in self.KNOWN_SAFE_PUBLIC_ENDPOINTS):
                continue
            try:
                response = await request_handler.get(url)
            except Exception:
                continue
            content_type = response.headers.get("content-type", "").lower()
            body = response.text.lower()
            looks_like_api_data = "application/json" in content_type or body.startswith("{") or body.startswith("[")
            sensitive_keywords = ("email", "role", "basket", "payment", "user")
            if (
                response.status_code == 200
                and looks_like_api_data
                and len(response.text) > 50
                and any(keyword in body for keyword in sensitive_keywords)
            ):
                findings.append(
                    Finding(
                        detector=self.name,
                        severity="high",
                        url=url,
                        evidence="Privileged-looking API returned structured data without an authenticated session.",
                        recommendation="Require authentication and authorization checks on privileged API routes.",
                        confidence="medium",
                        method="get",
                        category="route-access",
                        mutated_status=response.status_code,
                        mutated_length=len(response.text),
                        reason="Response looked like API data from a privileged route without an authenticated context.",
                    )
                )
        return findings
