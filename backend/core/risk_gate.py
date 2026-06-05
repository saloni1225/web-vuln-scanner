EXPOSURE_STATES = {
    "protected": "Protected",
    "monitoring": "Monitoring",
    "elevated": "Elevated Exposure",
    "investigate": "Investigate",
    "critical": "Critical Exposure",
    "drift": "Exposure Drift",
    "validation": "Validation Required",
}


def evaluate_exposure_posture(
    summary: dict[str, object] | None,
    *,
    exposure_intelligence: dict[str, object] | None = None,
    attack_surface_graph: dict[str, object] | None = None,
    auth_intelligence: dict[str, object] | None = None,
    drift_timeline: dict[str, object] | None = None,
    offensive_ai_intelligence: dict[str, object] | None = None,
    fail_on_high: bool = True,
    max_high: int = 0,
    max_medium: int | None = None,
    max_total: int | None = None,
) -> dict[str, object]:
    summary = summary or {}
    exposure_intelligence = exposure_intelligence or {}
    attack_surface_graph = attack_surface_graph or {}
    auth_intelligence = auth_intelligence or {}
    drift_timeline = drift_timeline or {}
    offensive_ai_intelligence = offensive_ai_intelligence or {}
    high_count = int(summary.get("high_severity_count", 0) or 0)
    medium_count = int(summary.get("medium_severity_count", 0) or 0)
    total_count = int(summary.get("finding_count", 0) or 0)
    internet_exposure = int(summary.get("endpoint_count", 0) or 0) + int(summary.get("api_endpoint_count", 0) or 0) + int(summary.get("open_port_count", 0) or 0)
    high_risk_endpoints = int(summary.get("high_risk_endpoint_count", 0) or 0)
    exposure_score = int(exposure_intelligence.get("score", 0) or 0)
    attack_paths = attack_surface_graph.get("attack_paths", []) if isinstance(attack_surface_graph.get("attack_paths", []), list) else []
    highest_path_score = max([int(path.get("risk_score", 0) or 0) for path in attack_paths if isinstance(path, dict)] or [0])
    auth_score = int(auth_intelligence.get("auth_exposure_score", 0) or auth_intelligence.get("score", 0) or 0)
    drift_count = int(drift_timeline.get("drift_event_count", 0) or 0)
    ai_predictions = offensive_ai_intelligence.get("exploitability_predictions", []) if isinstance(offensive_ai_intelligence.get("exploitability_predictions", []), list) else []
    exploitability_score = max([int(item.get("score", 0) or 0) for item in ai_predictions if isinstance(item, dict)] or [0])
    failures: list[str] = []
    reasoning: list[str] = []

    if fail_on_high and high_count > max_high:
        failures.append(f"{high_count} high severity findings exceeds allowed {max_high}")
        reasoning.append("High-severity findings require validation in the current policy.")
    if max_medium is not None and medium_count > max_medium:
        failures.append(f"{medium_count} medium severity findings exceeds allowed {max_medium}")
    if max_total is not None and total_count > max_total:
        failures.append(f"{total_count} total findings exceeds allowed {max_total}")

    posture_score = min(
        100,
        exposure_score
        + high_count * 8
        + high_risk_endpoints * 4
        + min(25, internet_exposure // 10)
        + min(25, highest_path_score // 4)
        + min(18, auth_score // 5)
        + min(16, drift_count * 2)
        + min(20, exploitability_score // 5),
    )
    if highest_path_score >= 85 or exploitability_score >= 90 or (high_count >= 3 and internet_exposure > 0):
        state_key = "critical"
    elif drift_count >= 3:
        state_key = "drift"
    elif high_count or highest_path_score >= 70 or auth_score >= 60:
        state_key = "investigate"
    elif medium_count or high_risk_endpoints or exposure_score >= 45:
        state_key = "elevated"
    elif total_count:
        state_key = "validation"
    elif internet_exposure:
        state_key = "monitoring"
    else:
        state_key = "protected"

    if highest_path_score:
        reasoning.append(f"Attack-path correlation reached {highest_path_score}.")
    if exploitability_score:
        reasoning.append(f"Exploitability prediction reached {exploitability_score}.")
    if auth_score:
        reasoning.append("Auth exposure contributes to posture.")
    if drift_count:
        reasoning.append(f"{drift_count} drift events affect exposure posture.")
    if high_risk_endpoints:
        reasoning.append(f"{high_risk_endpoints} high-risk endpoints are internet reachable.")

    gate_status = "failed" if failures else state_key

    return {
        "status": gate_status,
        "label": EXPOSURE_STATES[state_key],
        "posture": EXPOSURE_STATES[state_key],
        "score": posture_score,
        "passed": state_key in {"protected", "monitoring"},
        "failures": failures,
        "reasoning": reasoning or ["Exposure posture is based on internet reachability, drift, attack paths, and validation state."],
        "recommended_actions": _recommended_actions(state_key),
        "signals": {
            "exploitability_score": exploitability_score,
            "attack_path_score": highest_path_score,
            "internet_exposure": internet_exposure,
            "auth_exposure": auth_score,
            "api_sensitivity": int(summary.get("api_endpoint_count", 0) or 0),
            "drift_events": drift_count,
            "cloud_exposure": len(exposure_intelligence.get("priority_assets", []) or []),
        },
        "legacy_gate": {
            "status": "failed" if failures else "passed",
            "passed": not failures,
            "failures": failures,
        },
        "policy": {
            "fail_on_high": fail_on_high,
            "max_high": max_high,
            "max_medium": max_medium,
            "max_total": max_total,
        },
    }


def evaluate_risk_gate(summary: dict[str, object] | None, **kwargs) -> dict[str, object]:
    """Compatibility wrapper for old callers; returns the new exposure posture model."""
    return evaluate_exposure_posture(summary, **kwargs)


def _recommended_actions(state_key: str) -> list[str]:
    return {
        "critical": ["Open attack-path analysis", "Validate exploitability evidence", "Assign an owner immediately"],
        "drift": ["Review drift timeline", "Confirm newly exposed services", "Update monitoring scope"],
        "investigate": ["Inspect exposure reasoning", "Review auth and API exposure", "Validate correlated findings"],
        "elevated": ["Prioritize internet-facing assets", "Monitor exposure trend", "Schedule validation"],
        "validation": ["Confirm finding evidence", "Deduplicate related signals", "Retest after triage"],
        "monitoring": ["Keep continuous monitoring enabled", "Review changes weekly"],
        "protected": ["Maintain monitoring coverage", "Review posture after deployments"],
    }.get(state_key, ["Review exposure posture"])
