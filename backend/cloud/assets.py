from __future__ import annotations


def cloud_discovery_plan(target_host: str) -> dict[str, object]:
    normalized = target_host.replace(".", "-")
    return {
        "candidate_buckets": [normalized, f"{normalized}-assets", f"{normalized}-uploads", f"{normalized}-backup"],
        "providers": ["aws-s3", "azure-blob", "gcs"],
        "mode": "passive-candidate-analysis",
        "safety": "No write checks or destructive object operations are performed.",
    }

