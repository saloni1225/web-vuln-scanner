from __future__ import annotations


def predict_exploitability(finding: dict[str, object]) -> dict[str, object]:
    severity_weight = {"critical": 0.95, "high": 0.82, "medium": 0.55, "low": 0.25}.get(str(finding.get("severity", "low")), 0.4)
    confidence_weight = {"high": 0.12, "medium": 0.05, "low": -0.06}.get(str(finding.get("confidence", "medium")), 0.0)
    validation_weight = 0.08 if finding.get("validation_state") == "validated" else 0.0
    score = min(0.99, max(0.05, severity_weight + confidence_weight + validation_weight))
    return {
        "score": round(score, 2),
        "label": "likely exploitable" if score >= 0.75 else "needs analyst review" if score >= 0.45 else "low exploitability signal",
    }


def build_ai_risk_summary(findings: list[dict[str, object]], attack_surface: dict[str, object]) -> dict[str, object]:
    predictions = [{**finding, "exploitability": predict_exploitability(finding)} for finding in findings]
    high_value = [item for item in predictions if item["exploitability"]["score"] >= 0.75]
    return {
        "prioritized_finding_count": len(predictions),
        "high_exploitability_count": len(high_value),
        "top_findings": high_value[:10],
        "attack_chain_hypotheses": _attack_chains(predictions, attack_surface),
        "deduplication": {
            "strategy": "detector-url-parameter-payload hash clustering",
            "cluster_count": len({(item.get("detector"), item.get("url"), item.get("parameter")) for item in predictions}),
        },
    }


def _attack_chains(findings: list[dict[str, object]], attack_surface: dict[str, object]) -> list[dict[str, object]]:
    detectors = {str(item.get("detector")) for item in findings}
    chains = []
    if {"auth_bypass", "sqli"} & detectors:
        chains.append({"name": "auth-to-data-access", "confidence": "medium", "steps": ["authenticated surface", "authorization weakness", "data access finding"]})
    if attack_surface.get("high_risk_asset_count", 0) and findings:
        chains.append({"name": "public-critical-asset-exposure", "confidence": "medium", "steps": ["internet-facing asset", "validated finding", "remediation workflow"]})
    return chains

