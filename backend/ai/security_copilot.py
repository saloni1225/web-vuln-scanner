from __future__ import annotations


def generate_remediation_brief(finding: dict[str, object]) -> dict[str, object]:
    title = finding.get("title") or finding.get("detector") or "Security finding"
    return {
        "title": title,
        "summary": f"Review and remediate {title} with priority {finding.get('remediation_priority', 'P2')}.",
        "recommended_actions": [
            finding.get("recommendation") or "Validate input, enforce authorization, and add regression tests.",
            "Add a focused security test that reproduces the affected route and parameter.",
            "Retest through AdaptiveScan after deployment.",
        ],
        "owner_hint": "application-security",
    }

