def evaluate_risk_gate(
    summary: dict[str, object] | None,
    *,
    fail_on_high: bool = True,
    max_high: int = 0,
    max_medium: int | None = None,
    max_total: int | None = None,
) -> dict[str, object]:
    summary = summary or {}
    high_count = int(summary.get("high_severity_count", 0) or 0)
    medium_count = int(summary.get("medium_severity_count", 0) or 0)
    total_count = int(summary.get("finding_count", 0) or 0)
    failures: list[str] = []

    if fail_on_high and high_count > max_high:
        failures.append(f"{high_count} high severity findings exceeds allowed {max_high}")
    if max_medium is not None and medium_count > max_medium:
        failures.append(f"{medium_count} medium severity findings exceeds allowed {max_medium}")
    if max_total is not None and total_count > max_total:
        failures.append(f"{total_count} total findings exceeds allowed {max_total}")

    return {
        "status": "failed" if failures else "passed",
        "passed": not failures,
        "failures": failures,
        "policy": {
            "fail_on_high": fail_on_high,
            "max_high": max_high,
            "max_medium": max_medium,
            "max_total": max_total,
        },
    }
