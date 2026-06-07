"""
tests/test_canonical_schema.py

Tests for backend/core/finding_schema.py — the canonical finding model.
Verifies that the schema enforces minimum quality, normalizes enums,
computes deterministic fingerprints, and converts from legacy Finding dataclass.
"""
import pytest

from backend.core.finding_schema import (
    CanonicalFinding,
    ConfidenceLevel,
    EvidenceBundle,
    SeverityLevel,
    ValidationState,
)


# ---------------------------------------------------------------------------
# SeverityLevel enum
# ---------------------------------------------------------------------------

class TestSeverityLevel:
    def test_from_str_standard(self):
        assert SeverityLevel.from_str("high") == SeverityLevel.HIGH
        assert SeverityLevel.from_str("CRITICAL") == SeverityLevel.CRITICAL
        assert SeverityLevel.from_str("medium") == SeverityLevel.MEDIUM
        assert SeverityLevel.from_str("low") == SeverityLevel.LOW
        assert SeverityLevel.from_str("info") == SeverityLevel.INFO

    def test_from_str_aliases(self):
        assert SeverityLevel.from_str("informational") == SeverityLevel.INFO
        assert SeverityLevel.from_str("med") == SeverityLevel.MEDIUM
        assert SeverityLevel.from_str("none") == SeverityLevel.INFO

    def test_from_str_none_defaults_to_medium(self):
        assert SeverityLevel.from_str(None) == SeverityLevel.MEDIUM

    def test_from_str_unknown_defaults_to_medium(self):
        assert SeverityLevel.from_str("bogus") == SeverityLevel.MEDIUM

    def test_value_is_lowercase_string(self):
        assert SeverityLevel.HIGH.value == "high"
        assert SeverityLevel.CRITICAL.value == "critical"


# ---------------------------------------------------------------------------
# CanonicalFinding construction
# ---------------------------------------------------------------------------

class TestCanonicalFindingConstruction:
    def _make(self, **kwargs) -> CanonicalFinding:
        defaults = dict(
            detector="sqli",
            title="SQL Injection",
            description="Boolean-based blind SQLi",
            severity=SeverityLevel.HIGH,
            url="https://example.com/login",
            evidence="Response diff: baseline 200 vs mutated 500",
            recommendation="Use parameterized queries",
        )
        defaults.update(kwargs)
        return CanonicalFinding(**defaults)

    def test_required_fields_present(self):
        f = self._make()
        assert f.detector == "sqli"
        assert f.title == "SQL Injection"
        assert f.severity == SeverityLevel.HIGH
        assert f.url == "https://example.com/login"

    def test_finding_id_auto_generated(self):
        f = self._make()
        assert f.finding_id and len(f.finding_id) > 0

    def test_fingerprint_computed_on_init(self):
        f = self._make()
        assert f.fingerprint and len(f.fingerprint) == 16  # SHA-256 truncated to 16 hex chars

    def test_fingerprint_is_deterministic(self):
        """Same detector+url+parameter+payload must produce same fingerprint."""
        bundle = EvidenceBundle(parameter="id", payload="' OR 1=1--")
        f1 = self._make(evidence_bundle=bundle)
        f2 = self._make(evidence_bundle=bundle)
        assert f1.fingerprint == f2.fingerprint

    def test_fingerprint_differs_on_different_payload(self):
        b1 = EvidenceBundle(parameter="id", payload="' OR 1=1--")
        b2 = EvidenceBundle(parameter="id", payload="' OR 1=2--")
        f1 = self._make(evidence_bundle=b1)
        f2 = self._make(evidence_bundle=b2)
        assert f1.fingerprint != f2.fingerprint

    def test_severity_normalized_from_string(self):
        f = self._make(severity="CRITICAL")
        assert f.severity == SeverityLevel.CRITICAL

    def test_confidence_defaults_to_medium(self):
        f = self._make()
        assert f.confidence == ConfidenceLevel.MEDIUM

    def test_validation_state_defaults_to_unvalidated(self):
        f = self._make()
        assert f.validation_state == ValidationState.UNVALIDATED

    def test_title_derived_when_missing(self):
        f = CanonicalFinding(
            detector="xss",
            title="",
            description="Reflected XSS",
            severity=SeverityLevel.MEDIUM,
            url="https://example.com/search",
            evidence="Payload reflected",
            recommendation="Encode output",
        )
        assert "xss" in f.title.lower() or "example.com" in f.title.lower()

    def test_description_falls_back_to_evidence(self):
        f = CanonicalFinding(
            detector="csrf",
            title="CSRF",
            description="",
            severity=SeverityLevel.MEDIUM,
            url="https://example.com/form",
            evidence="No CSRF token present",
            recommendation="Add CSRF token",
        )
        assert f.description == "No CSRF token present"


# ---------------------------------------------------------------------------
# to_dict serialization
# ---------------------------------------------------------------------------

class TestCanonicalFindingToDict:
    def _make(self) -> CanonicalFinding:
        return CanonicalFinding(
            detector="idor",
            title="IDOR in user profile",
            description="Access to another user's profile via user_id manipulation",
            severity=SeverityLevel.HIGH,
            url="https://example.com/profile/2",
            evidence="Access granted to user_id=2 when authenticated as user_id=1",
            recommendation="Enforce ownership checks server-side",
            cwe_id="CWE-639",
            cvss_score=8.1,
            evidence_bundle=EvidenceBundle(parameter="user_id", payload="2"),
        )

    def test_to_dict_contains_required_fields(self):
        d = self._make().to_dict()
        for key in ["finding_id", "fingerprint", "detector", "title", "description",
                    "severity", "url", "evidence", "recommendation", "confidence",
                    "validation_state"]:
            assert key in d, f"Missing key: {key}"

    def test_severity_serialized_as_string(self):
        d = self._make().to_dict()
        assert d["severity"] == "high"

    def test_confidence_serialized_as_string(self):
        d = self._make().to_dict()
        assert d["confidence"] == "medium"

    def test_evidence_bundle_included(self):
        d = self._make().to_dict()
        assert "evidence_bundle" in d
        assert d["evidence_bundle"]["parameter"] == "user_id"

    def test_none_values_not_in_evidence_bundle(self):
        bundle = EvidenceBundle(parameter="q")  # all others None
        f = CanonicalFinding(
            detector="xss", title="XSS", description="XSS",
            severity=SeverityLevel.LOW, url="https://example.com",
            evidence="reflected", recommendation="encode output",
            evidence_bundle=bundle,
        )
        bundle_dict = f.to_dict()["evidence_bundle"]
        assert "parameter" in bundle_dict
        # None values should not be included
        assert "request_snapshot" not in bundle_dict


# ---------------------------------------------------------------------------
# Validation quality check
# ---------------------------------------------------------------------------

class TestCanonicalFindingValidation:
    def test_complete_finding_has_no_warnings(self):
        f = CanonicalFinding(
            detector="sqli",
            title="SQL Injection",
            description="Detailed description",
            severity=SeverityLevel.HIGH,
            url="https://example.com/api",
            evidence="Payload caused 500 error",
            recommendation="Use parameterized queries",
            cwe_id="CWE-89",
            evidence_bundle=EvidenceBundle(
                parameter="id",
                payload="' OR 1=1--",
                request_snapshot="GET /api?id=1' HTTP/1.1",
            ),
        )
        warnings = f.validate()
        assert warnings == []

    def test_missing_cwe_generates_warning(self):
        f = CanonicalFinding(
            detector="sqli",
            title="SQL Injection",
            description="desc",
            severity=SeverityLevel.HIGH,
            url="https://example.com",
            evidence="some evidence",
            recommendation="fix it",
        )
        warnings = f.validate()
        assert any("CWE" in w for w in warnings)

    def test_missing_evidence_generates_warning(self):
        f = CanonicalFinding(
            detector="csrf",
            title="CSRF",
            description="desc",
            severity=SeverityLevel.MEDIUM,
            url="https://example.com",
            evidence="",
            recommendation="fix it",
        )
        warnings = f.validate()
        assert any("evidence" in w.lower() for w in warnings)


# ---------------------------------------------------------------------------
# from_finding() legacy conversion
# ---------------------------------------------------------------------------

class TestFromFindingConversion:
    def test_converts_from_base_finding_dataclass(self):
        """Ensure we can convert from the existing Finding dataclass."""
        from backend.detection.base_detector import Finding

        legacy = Finding(
            detector="xss",
            severity="high",
            url="https://example.com/search?q=test",
            evidence="Payload <script> reflected in response",
            recommendation="Encode output",
            parameter="q",
            payload="<script>alert(1)</script>",
            confidence="high",
            confidence_score=0.9,
            baseline_status=200,
            mutated_status=200,
            validation_state="confirmed",
        )

        canonical = CanonicalFinding.from_finding(legacy)
        assert canonical.detector == "xss"
        assert canonical.severity == SeverityLevel.HIGH
        assert canonical.confidence == ConfidenceLevel.HIGH
        assert canonical.confidence_score == 0.9
        assert canonical.validation_state == ValidationState.CONFIRMED
        assert canonical.evidence_bundle is not None
        assert canonical.evidence_bundle.parameter == "q"
        assert canonical.evidence_bundle.payload == "<script>alert(1)</script>"

    def test_from_finding_generates_title_if_missing(self):
        """Legacy findings don't have a title field — one should be generated."""
        from backend.detection.base_detector import Finding

        legacy = Finding(
            detector="csrf",
            severity="medium",
            url="https://example.com/form",
            evidence="No CSRF token in form",
            recommendation="Add CSRF token",
        )
        canonical = CanonicalFinding.from_finding(legacy)
        assert canonical.title  # Must not be empty
        assert len(canonical.title) > 5
