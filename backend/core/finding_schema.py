"""
backend/core/finding_schema.py — Canonical Finding Schema

This module defines the single source of truth for all findings emitted
by the AdaptiveScan detection engine.

DESIGN PRINCIPLES:
- All detectors MUST produce findings that validate against CanonicalFinding.
- The schema is intentionally additive: required fields ensure minimum quality;
  optional fields allow detectors to provide richer context.
- Findings are deduplicated via a deterministic fingerprint:
    SHA-256(detector + url + parameter + payload)
- Severity and confidence are constrained enums to prevent inconsistent strings.

USAGE:
    from backend.core.finding_schema import CanonicalFinding, SeverityLevel, ConfidenceLevel

    # Convert from base Finding dataclass
    canonical = CanonicalFinding.from_finding(finding)

    # Or build directly
    f = CanonicalFinding(
        detector="sqli",
        title="SQL Injection in login form",
        description="Boolean-based blind SQLi detected via error response differential.",
        severity=SeverityLevel.HIGH,
        url="https://example.com/login",
        evidence="Payload ' OR 1=1-- returned 200 vs baseline 403",
        recommendation="Use parameterized queries or prepared statements.",
    )
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_str(cls, value: str | None) -> "SeverityLevel":
        if not value:
            return cls.MEDIUM
        normalized = value.strip().lower()
        try:
            return cls(normalized)
        except ValueError:
            # Map legacy severity strings
            mapping = {"critical": cls.CRITICAL, "high": cls.HIGH, "med": cls.MEDIUM,
                       "medium": cls.MEDIUM, "low": cls.LOW, "info": cls.INFO,
                       "informational": cls.INFO, "none": cls.INFO}
            return mapping.get(normalized, cls.MEDIUM)


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    TENTATIVE = "tentative"

    @classmethod
    def from_str(cls, value: str | None) -> "ConfidenceLevel":
        if not value:
            return cls.MEDIUM
        normalized = value.strip().lower()
        try:
            return cls(normalized)
        except ValueError:
            return cls.MEDIUM


class ValidationState(str, Enum):
    UNVALIDATED = "unvalidated"
    CONFIRMED = "confirmed"
    FLAKY = "flaky"
    FALSE_POSITIVE = "false_positive"
    PENDING = "pending"

    @classmethod
    def from_str(cls, value: str | None) -> "ValidationState":
        if not value:
            return cls.UNVALIDATED
        normalized = value.strip().lower().replace("-", "_")
        try:
            return cls(normalized)
        except ValueError:
            return cls.UNVALIDATED


@dataclass
class EvidenceBundle:
    """
    Structured evidence for a finding — everything needed to reproduce it.
    """
    # HTTP evidence
    request_snapshot: str | None = None    # Raw HTTP request (full, not truncated)
    response_snapshot: str | None = None   # Raw HTTP response (full, not truncated)
    baseline_status: int | None = None     # Status code before mutation
    mutated_status: int | None = None      # Status code after mutation
    baseline_length: int | None = None     # Response length before mutation
    mutated_length: int | None = None      # Response length after mutation
    timing_ms: float | None = None         # Response time in milliseconds

    # Payload details
    parameter: str | None = None           # Affected parameter name
    payload: str | None = None             # Injected payload
    input_location: str | None = None      # e.g., "query", "header", "body", "cookie"

    # Contextual evidence
    reflection_context: str | None = None  # e.g., "script", "attribute", "text"
    dom_observation: str | None = None     # DOM-based XSS observation
    code_snippet: str | None = None        # Vulnerable code excerpt (if known)
    reason: str | None = None              # Human-readable reason for flagging
    validation_signals: list[str] | None = None  # e.g., ["status_diff", "length_diff"]

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class CanonicalFinding:
    """
    The normalized finding model used by all detectors, validators,
    report generators, correlation engine, and evidence bundler.

    REQUIRED fields must be populated by every detector.
    OPTIONAL fields are populated by enrichment, validation, or correlation.
    """
    # ── REQUIRED ────────────────────────────────────────────────────────────
    detector: str                          # Detector name (e.g., "sqli", "xss")
    title: str                             # Short human-readable title
    description: str                       # Detailed description of the issue
    severity: SeverityLevel                # Normalized severity enum
    url: str                               # Affected URL
    evidence: str                          # Human-readable evidence summary
    recommendation: str                    # Remediation guidance

    # ── IDENTITY ─────────────────────────────────────────────────────────────
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    fingerprint: str = field(default="")  # Deterministic dedup hash (computed post-init)

    # ── CONFIDENCE & VALIDATION ──────────────────────────────────────────────
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    confidence_score: float | None = None  # 0.0–1.0 numeric confidence
    validation_state: ValidationState = ValidationState.UNVALIDATED
    method: str = "get"                    # HTTP method used
    category: str = "generic"             # Detector category

    # ── CLASSIFICATION ────────────────────────────────────────────────────────
    cwe_id: str | None = None              # e.g., "CWE-89"
    cwe_title: str | None = None           # e.g., "SQL Injection"
    cvss_score: float | None = None        # CVSS v3.1 numeric score
    cvss_vector: str | None = None         # e.g., "CVSS:3.1/AV:N/AC:L/..."
    owasp_category: str | None = None      # OWASP Top 10 category
    remediation_priority: str | None = None # "immediate", "high", "medium", "low"

    # ── ASSET CONTEXT ─────────────────────────────────────────────────────────
    affected_asset: str | None = None      # Asset identifier (hostname, endpoint)
    poc: str | None = None                 # Proof-of-concept URL or command

    # ── EVIDENCE BUNDLE ───────────────────────────────────────────────────────
    evidence_bundle: EvidenceBundle | None = None

    # ── CORRELATION ───────────────────────────────────────────────────────────
    parent_findings: list[str] | None = None    # IDs of findings this chains from
    attack_chain_ids: list[str] | None = None   # Attack chain identifiers (e.g., AC-001)

    def __post_init__(self) -> None:
        # Compute deterministic fingerprint for deduplication
        if not self.fingerprint:
            self.fingerprint = self._compute_fingerprint()

        # Normalize enums from strings if plain strings were passed
        if isinstance(self.severity, str):
            self.severity = SeverityLevel.from_str(self.severity)
        if isinstance(self.confidence, str):
            self.confidence = ConfidenceLevel.from_str(self.confidence)
        if isinstance(self.validation_state, str):
            self.validation_state = ValidationState.from_str(self.validation_state)

        # Ensure title is set (derive from detector if missing)
        if not self.title:
            self.title = f"{self.detector.upper()} finding at {self.url}"

        # Ensure description is set
        if not self.description:
            self.description = self.evidence

    def _compute_fingerprint(self) -> str:
        """
        Deterministic SHA-256 fingerprint for deduplication across scans.
        Two findings are considered the same vulnerability if they share:
        detector + url + parameter + payload
        """
        param = ""
        payload = ""
        if self.evidence_bundle:
            param = self.evidence_bundle.parameter or ""
            payload = self.evidence_bundle.payload or ""
        raw = f"{self.detector}|{self.url}|{param}|{payload}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def from_finding(cls, finding: Any) -> "CanonicalFinding":
        """
        Convert a base Finding dataclass instance into a CanonicalFinding.
        Handles missing fields gracefully to support all detector quality levels.
        """
        d = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)

        evidence_bundle = EvidenceBundle(
            request_snapshot=d.get("request_snapshot"),
            response_snapshot=d.get("response_snapshot"),
            baseline_status=d.get("baseline_status"),
            mutated_status=d.get("mutated_status"),
            baseline_length=d.get("baseline_length"),
            mutated_length=d.get("mutated_length"),
            parameter=d.get("parameter"),
            payload=d.get("payload"),
            input_location=d.get("input_location"),
            reflection_context=d.get("reflection_context"),
            dom_observation=d.get("dom_observation"),
            code_snippet=d.get("code_snippet"),
            reason=d.get("reason"),
            validation_signals=d.get("validation_signals"),
        )

        # Derive title from detector if not set
        detector = d.get("detector", "unknown")
        url = d.get("url", "")
        title = d.get("title") or f"{detector.upper()} vulnerability at {url}"
        description = d.get("description") or d.get("evidence", "")

        return cls(
            detector=detector,
            title=title,
            description=description,
            severity=SeverityLevel.from_str(d.get("severity")),
            url=url,
            evidence=d.get("evidence", ""),
            recommendation=d.get("recommendation", ""),
            finding_id=d.get("finding_id") or str(uuid.uuid4()),
            confidence=ConfidenceLevel.from_str(d.get("confidence")),
            confidence_score=d.get("confidence_score"),
            validation_state=ValidationState.from_str(d.get("validation_state")),
            method=d.get("method", "get"),
            category=d.get("category", "generic"),
            cwe_id=d.get("cwe_id"),
            cwe_title=d.get("cwe_title"),
            cvss_score=d.get("cvss_score"),
            cvss_vector=d.get("cvss_vector"),
            owasp_category=d.get("owasp_category"),
            remediation_priority=d.get("remediation_priority"),
            affected_asset=d.get("affected_asset"),
            poc=d.get("poc"),
            evidence_bundle=evidence_bundle,
            parent_findings=d.get("parent_findings"),
            attack_chain_ids=d.get("attack_chain_ids"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict for API responses and DB storage."""
        result = {
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
            "detector": self.detector,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "url": self.url,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "confidence": self.confidence.value,
            "confidence_score": self.confidence_score,
            "validation_state": self.validation_state.value,
            "method": self.method,
            "category": self.category,
            "cwe_id": self.cwe_id,
            "cwe_title": self.cwe_title,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "owasp_category": self.owasp_category,
            "remediation_priority": self.remediation_priority,
            "affected_asset": self.affected_asset,
            "poc": self.poc,
            "parent_findings": self.parent_findings,
            "attack_chain_ids": self.attack_chain_ids,
            # Backward compatibility fields
            "parameter": None,
            "payload": None,
            "request_snapshot": None,
            "response_snapshot": None,
            "baseline_status": None,
            "mutated_status": None,
            "baseline_length": None,
            "mutated_length": None,
            "reason": None,
            "input_location": None,
            "reflection_context": None,
            "dom_observation": None,
            "code_snippet": None,
            "validation_signals": None,
        }
        if self.evidence_bundle:
            result["evidence_bundle"] = self.evidence_bundle.to_dict()
            # Populate backward compatibility fields from evidence bundle
            result["parameter"] = self.evidence_bundle.parameter
            result["payload"] = self.evidence_bundle.payload
            result["request_snapshot"] = self.evidence_bundle.request_snapshot
            result["response_snapshot"] = self.evidence_bundle.response_snapshot
            result["baseline_status"] = self.evidence_bundle.baseline_status
            result["mutated_status"] = self.evidence_bundle.mutated_status
            result["baseline_length"] = self.evidence_bundle.baseline_length
            result["mutated_length"] = self.evidence_bundle.mutated_length
            result["reason"] = self.evidence_bundle.reason
            result["input_location"] = self.evidence_bundle.input_location
            result["reflection_context"] = self.evidence_bundle.reflection_context
            result["dom_observation"] = self.evidence_bundle.dom_observation
            result["code_snippet"] = self.evidence_bundle.code_snippet
            result["validation_signals"] = self.evidence_bundle.validation_signals
        return result

    def validate(self) -> list[str]:
        """
        Validate the finding for minimum quality. Returns a list of warning strings.
        Warnings do not block the finding from being stored, but are logged.
        """
        warnings = []
        if not self.title or self.title.startswith("unknown"):
            warnings.append(f"[{self.detector}] Missing or generic title")
        if not self.evidence:
            warnings.append(f"[{self.detector}] No evidence provided")
        if not self.recommendation:
            warnings.append(f"[{self.detector}] No remediation recommendation")
        if not self.cwe_id:
            warnings.append(f"[{self.detector}] No CWE mapping")
        if self.evidence_bundle and not (
            self.evidence_bundle.request_snapshot or self.evidence_bundle.payload
        ):
            warnings.append(f"[{self.detector}] Evidence bundle has no request snapshot or payload")
        return warnings

    @property
    def parameter(self) -> str | None:
        return self.evidence_bundle.parameter if self.evidence_bundle else None

    @property
    def payload(self) -> str | None:
        return self.evidence_bundle.payload if self.evidence_bundle else None

    @property
    def request_snapshot(self) -> str | None:
        return self.evidence_bundle.request_snapshot if self.evidence_bundle else None

    @property
    def response_snapshot(self) -> str | None:
        return self.evidence_bundle.response_snapshot if self.evidence_bundle else None

    @property
    def baseline_status(self) -> int | None:
        return self.evidence_bundle.baseline_status if self.evidence_bundle else None

    @property
    def mutated_status(self) -> int | None:
        return self.evidence_bundle.mutated_status if self.evidence_bundle else None

    @property
    def baseline_length(self) -> int | None:
        return self.evidence_bundle.baseline_length if self.evidence_bundle else None

    @property
    def mutated_length(self) -> int | None:
        return self.evidence_bundle.mutated_length if self.evidence_bundle else None
