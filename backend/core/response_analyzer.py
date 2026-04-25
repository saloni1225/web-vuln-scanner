import html
import re

from backend.core.request_handler import HttpResponse


ERROR_PATTERNS = [
    "sql syntax",
    "mysql",
    "postgresql",
    "sqlite",
    "ora-",
    "warning:",
    "stack trace",
    "traceback",
]


class ResponseAnalyzer:
    def has_error_signature(self, response: HttpResponse) -> bool:
        body = response.text.lower()
        return any(pattern in body for pattern in ERROR_PATTERNS)

    def has_reflection(self, response: HttpResponse, marker: str) -> bool:
        return marker in response.text

    def has_status_anomaly(self, baseline: HttpResponse, candidate: HttpResponse) -> bool:
        return baseline.status_code != candidate.status_code or abs(baseline.elapsed_ms - candidate.elapsed_ms) > 1500

    def has_length_anomaly(self, baseline: HttpResponse, candidate: HttpResponse, ratio: float = 0.35) -> bool:
        baseline_length = max(1, len(baseline.text))
        candidate_length = len(candidate.text)
        return abs(candidate_length - baseline_length) / baseline_length >= ratio

    def classify_reflection_context(self, response: HttpResponse, marker: str) -> dict[str, object]:
        body = response.text
        contexts: list[str] = []
        escaped_marker = html.escape(marker, quote=True)
        if marker in body:
            contexts.append("body")
        if escaped_marker in body and escaped_marker != marker:
            contexts.append("encoded")
        if re.search(rf"<script[^>]*>[^<]*{re.escape(marker)}", body, re.IGNORECASE):
            contexts.append("script")
        if re.search(rf"\w+\s*=\s*['\"][^'\"]*{re.escape(marker)}[^'\"]*['\"]", body, re.IGNORECASE):
            contexts.append("attribute")
        if re.search(rf"<[^>]+>{re.escape(marker)}</", body, re.IGNORECASE):
            contexts.append("dom-text")
        dangerous_contexts = [item for item in contexts if item in {"script", "attribute"}]
        return {
            "reflected": bool(contexts),
            "contexts": list(dict.fromkeys(contexts)),
            "dangerous": bool(dangerous_contexts),
            "encoded_only": contexts == ["encoded"],
        }
