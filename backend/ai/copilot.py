from __future__ import annotations


def ai_copilot_capabilities() -> dict[str, object]:
    return {
        "provider_abstraction": ["local", "hugging_face", "openai_compatible"],
        "capabilities": [
            "risk_prioritization",
            "finding_deduplication",
            "executive_summaries",
            "remediation_suggestions",
            "exposure_explanations",
            "attack_path_explanation",
            "exploitability_prediction",
        ],
        "panel": {
            "name": "AdaptiveScan AI Copilot",
            "placement": "enterprise right rail and finding detail drawer",
            "actions": ["explain exposure", "summarize report", "prioritize fixes", "draft remediation"],
        },
        "safety": ["tenant scoped context", "evidence-grounded responses", "no autonomous exploitation"],
    }


def ai_copilot_response(prompt: str = "") -> dict[str, object]:
    return {
        "answer": "Prioritize internet-facing assets with critical findings, recent drift, and authentication exposure before lower-confidence scan noise.",
        "prompt": prompt,
        "recommended_actions": [
            "Assign owner to critical external findings.",
            "Enable daily monitoring for high-value domains.",
            "Export executive summary after remediation plan approval.",
        ],
        "confidence": "high",
    }
