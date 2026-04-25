from backend.core.request_handler import RequestHandler
from backend.detection.base_detector import BaseDetector, Finding


class CsrfDetector(BaseDetector):
    name = "csrf"

    async def detect(
        self,
        target_url: str,
        site_map: dict[str, object],
        request_handler: RequestHandler,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for form in site_map.get("forms", []):
            inputs = [str(name).lower() for name in form.get("inputs", [])] if isinstance(form, dict) else []
            method = str(form.get("method", "get")).lower() if isinstance(form, dict) else "get"
            if method == "post" and not any("csrf" in name or "token" in name for name in inputs):
                findings.append(
                    Finding(
                        detector=self.name,
                        severity="medium",
                        url=str(form.get("action", target_url)),
                        evidence="POST form does not expose an obvious CSRF token field",
                        recommendation="Add per-request CSRF tokens and validate them server-side.",
                        confidence="medium",
                        method="post",
                        category="form-field",
                    )
                )
        return findings
