from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass

from backend.core.request_handler import RequestHandler


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
    cvss_score: float | None = None
    remediation_priority: str | None = None
    poc: str | None = None
    validation_state: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)


class BaseDetector(ABC):
    name = "base"

    @abstractmethod
    async def detect(
        self,
        target_url: str,
        site_map: dict[str, object],
        request_handler: RequestHandler,
    ) -> list[Finding]:
        raise NotImplementedError
