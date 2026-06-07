from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

from backend.core.request_handler import RequestHandler


STATE_CHANGING_PATH_HINTS = (
    "/api/delivery",
    "/api/hint",
    "/api/feedback",
    "/api/basket",
    "/api/order",
    "/api/card",
    "/api/address",
    "/api/user",
    "/api/security",
    "/rest/user",
    "/rest/basket",
    "/rest/order",
)
AUTH_ENDPOINT_HINTS = (
    "/login",
    "/logout",
    "/signin",
    "/sign-in",
    "/signup",
    "/sign-up",
    "/rest/user/login",
    "/saveLoginIp",
)
LOW_RISK_POST_HINTS = (
    "/search",
    "/graphql",
    "/api/graphql",
)


@dataclass(slots=True)
class Finding:
    detector: str
    severity: str
    url: str
    evidence: str
    recommendation: str
    confidence: str = "medium"
    parameter: str | None = None
    payload: str | None = None
    method: str = "get"
    category: str = "generic"
    baseline_status: int | None = None
    mutated_status: int | None = None
    baseline_length: int | None = None
    mutated_length: int | None = None
    reason: str | None = None
    input_location: str | None = None
    reflection_context: str | None = None
    dom_observation: str | None = None
    confidence_score: float | None = None
    validation_signals: list[str] | None = None
    finding_id: str | None = None
    request_snapshot: str | None = None
    response_snapshot: str | None = None
    cwe_id: str | None = None
    cwe_title: str | None = None
    cvss_score: float | None = None
    remediation_priority: str | None = None
    poc: str | None = None
    validation_state: str | None = None
    owasp_category: str | None = None
    code_snippet: str | None = None
    cvss_vector: str | None = None
    parent_findings: list[str] | None = None
    attack_chain_ids: list[str] | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class BaseDetector(ABC):
    name = "base"

    @staticmethod
    def allow_active_post_probe(form: dict[str, object], site_map: dict[str, object]) -> bool:
        action = str(form.get("action", "")).lower()
        content_type = str(form.get("content_type", "form")).lower()
        source = str(form.get("source", "")).lower()
        if any(hint in action for hint in AUTH_ENDPOINT_HINTS):
            return bool(site_map.get("allow_auth_endpoint_fuzz"))
        if site_map.get("allow_state_changing_fuzz"):
            return True
        if any(hint in action for hint in LOW_RISK_POST_HINTS):
            return True
        if any(hint in action for hint in STATE_CHANGING_PATH_HINTS):
            return False
        if content_type == "json" or "api" in action or "schema" in source:
            return False
        parsed = urlparse(action)
        return parsed.path in {"", "/"} or not parsed.path.lower().startswith(("/api", "/rest"))

    @abstractmethod
    async def detect(
        self,
        target_url: str,
        site_map: dict[str, object],
        request_handler: RequestHandler,
    ) -> list[Finding]:
        raise NotImplementedError
