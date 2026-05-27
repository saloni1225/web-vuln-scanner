from backend.core.enterprise_foundation import get_enterprise_foundation


def test_enterprise_foundation_exposes_lifecycle_compliance_and_ci_templates():
    foundation = get_enterprise_foundation()

    assert [item["state"] for item in foundation["lifecycle"]] == [
        "open",
        "triaged",
        "assigned",
        "retesting",
        "resolved",
        "closed",
    ]
    assert {item["framework"] for item in foundation["compliance"]} >= {"OWASP Top 10", "PCI DSS", "ISO 27001", "NIST"}
    assert {item["platform"] for item in foundation["ci_templates"]} >= {"GitHub Actions", "GitLab CI", "Jenkins", "Azure DevOps"}
    assert len(foundation["distributed_architecture"]) >= 6
