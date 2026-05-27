from __future__ import annotations


FRAMEWORK_MAPPINGS = {
    "OWASP ASVS": ["V5", "V7", "V10", "V14"],
    "OWASP Top 10": ["A01", "A03", "A05", "A07"],
    "PCI DSS 4.0": ["6.2", "6.3", "6.4", "11.3"],
    "ISO 27001": ["A.8.8", "A.8.16", "A.8.28"],
    "NIST CSF": ["ID.RA", "DE.CM", "RS.AN"],
}


def build_compliance_summary(findings: list[dict[str, object]]) -> dict[str, object]:
    mapped_findings = []
    for finding in findings:
        mapped_findings.append(
            {
                "title": finding.get("title") or finding.get("detector"),
                "severity": finding.get("severity", "low"),
                "cwe": finding.get("cwe_id", ""),
                "frameworks": FRAMEWORK_MAPPINGS,
            }
        )
    return {
        "frameworks": [
            {"framework": framework, "controls": controls, "mapped_findings": len(mapped_findings)}
            for framework, controls in FRAMEWORK_MAPPINGS.items()
        ],
        "mapped_finding_count": len(mapped_findings),
        "evidence_bundle_ready": True,
        "mapped_findings": mapped_findings[:100],
    }

