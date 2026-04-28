import html
import json
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

    def has_boolean_response_delta(
        self,
        baseline: HttpResponse,
        truthy: HttpResponse,
        falsy: HttpResponse,
        ratio: float = 0.18,
    ) -> bool:
        truthy_length = len(truthy.text)
        falsy_length = len(falsy.text)
        baseline_length = max(1, len(baseline.text))
        truthy_delta = abs(truthy_length - baseline_length) / baseline_length
        falsy_delta = abs(falsy_length - baseline_length) / baseline_length
        truthy_falsy_delta = abs(truthy_length - falsy_length) / baseline_length
        status_split = truthy.status_code != falsy.status_code
        statuses_stable = truthy.status_code < 500 and falsy.status_code < 500
        return status_split or (statuses_stable and truthy_falsy_delta >= ratio and abs(truthy_delta - falsy_delta) >= 0.08)

    def has_time_delay_anomaly(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        threshold_ms: float = 3500,
    ) -> bool:
        return candidate.elapsed_ms - baseline.elapsed_ms >= threshold_ms and candidate.status_code < 500

    def classify_reflection_context(self, response: HttpResponse, marker: str) -> dict[str, object]:
        body = response.text
        contexts: list[str] = []
        escaped_marker = html.escape(marker, quote=True)
        json_marker = json.dumps(marker)
        if marker in body:
            contexts.append("body")
        if escaped_marker in body and escaped_marker != marker:
            contexts.append("encoded")
        if json_marker in body:
            contexts.append("json")
        if re.search(rf"<script[^>]*>[^<]*{re.escape(marker)}", body, re.IGNORECASE):
            contexts.append("script")
        if re.search(rf"\w+\s*=\s*['\"][^'\"]*{re.escape(marker)}[^'\"]*['\"]", body, re.IGNORECASE):
            contexts.append("attribute")
        if re.search(rf"<[^>]+>{re.escape(marker)}</", body, re.IGNORECASE):
            contexts.append("dom-text")
        if re.search(rf"`[^`]*{re.escape(marker)}[^`]*`", body):
            contexts.append("js_template_literal")
        if re.search(rf"href\s*=\s*['\"]javascript:[^'\"]*{re.escape(marker)}", body, re.IGNORECASE):
            contexts.append("href_javascript")
        dangerous_contexts = [item for item in contexts if item in {"script", "attribute", "js_template_literal", "href_javascript"}]
        return {
            "reflected": bool(contexts),
            "contexts": list(dict.fromkeys(contexts)),
            "dangerous": bool(dangerous_contexts),
            "encoded_only": contexts == ["encoded"],
        }

    def classify_confidence(
        self,
        *,
        error_signature: bool = False,
        boolean_delta: bool = False,
        time_delay: bool = False,
        dangerous_reflection: bool = False,
        stable_reflection: bool = False,
        stored_indicator: bool = False,
        anomaly_score: float = 0.0,
    ) -> dict[str, object]:
        signals: list[str] = []
        score = 0.0

        if error_signature:
            score += 0.42
            signals.append("error-signature")
        if boolean_delta:
            score += 0.34
            signals.append("boolean-delta")
        if time_delay:
            score += 0.34
            signals.append("time-delay")
        if dangerous_reflection:
            score += 0.42
            signals.append("dangerous-reflection")
        if stable_reflection:
            score += 0.24
            signals.append("stable-reflection")
        if stored_indicator:
            score += 0.34
            signals.append("stored-indicator")

        if anomaly_score >= 0.65:
            score += 0.2
            signals.append("high-anomaly")
        elif anomaly_score >= 0.35:
            score += 0.1
            signals.append("moderate-anomaly")

        score = round(min(1.0, score), 2)
        if score >= 0.75:
            confidence = "high"
            validation_state = "validated"
        elif score >= 0.45:
            confidence = "medium"
            validation_state = "triaged"
        else:
            confidence = "low"
            validation_state = "requires-review"

        return {
            "confidence": confidence,
            "confidence_score": score,
            "validation_state": validation_state,
            "signals": signals,
        }

    def summarize_response_diff(self, baseline: HttpResponse, candidate: HttpResponse) -> dict[str, object]:
        baseline_length = len(baseline.text)
        candidate_length = len(candidate.text)
        delta = candidate_length - baseline_length
        ratio = round(abs(delta) / max(1, baseline_length), 3)
        changed_headers = sorted(
            {
                key.lower()
                for key in set(baseline.headers) | set(candidate.headers)
                if baseline.headers.get(key) != candidate.headers.get(key)
            }
        )
        return {
            "status_changed": baseline.status_code != candidate.status_code,
            "length_delta": delta,
            "length_ratio": ratio,
            "latency_delta_ms": round(candidate.elapsed_ms - baseline.elapsed_ms, 2),
            "changed_headers": changed_headers[:8],
        }

    def anomaly_score(self, baseline: HttpResponse, candidate: HttpResponse) -> float:
        diff = self.summarize_response_diff(baseline, candidate)
        score = 0.0
        if diff["status_changed"]:
            score += 0.45
        score += min(0.35, float(diff["length_ratio"]) * 0.7)
        latency_delta = max(0.0, float(diff["latency_delta_ms"]))
        score += min(0.2, latency_delta / 5000)
        return round(min(1.0, score), 2)

    def snapshot_response(self, response: HttpResponse, limit: int = 220) -> str:
        body = response.text.strip().replace("\n", " ")
        if len(body) <= limit:
            return body
        return f"{body[:limit]}..."
