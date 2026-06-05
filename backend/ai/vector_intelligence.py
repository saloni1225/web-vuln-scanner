from __future__ import annotations

from backend.ai.embeddings import EmbeddingEngine


class VectorIntelligenceService:
    def __init__(self, engine: EmbeddingEngine | None = None) -> None:
        self.engine = engine or EmbeddingEngine()

    def cluster_findings(self, findings: list[dict[str, object]]) -> list[dict[str, object]]:
        clusters: list[dict[str, object]] = []
        for finding in findings:
            text = _finding_text(finding)
            assigned = False
            for cluster in clusters:
                similarity = self.engine.similarity(text, str(cluster["representative_text"]))
                if similarity >= 0.72:
                    cluster["count"] = int(cluster["count"]) + 1
                    cluster["members"].append(finding)
                    cluster["max_similarity"] = max(float(cluster.get("max_similarity", 0)), similarity)
                    assigned = True
                    break
            if not assigned:
                clusters.append(
                    {
                        "cluster_id": f"cluster-{len(clusters) + 1}",
                        "representative_text": text,
                        "title": finding.get("detector") or finding.get("category") or "finding",
                        "severity": finding.get("severity", "medium"),
                        "count": 1,
                        "max_similarity": 1.0,
                        "members": [finding],
                    }
                )
        return [_compact_cluster(cluster) for cluster in clusters[:50]]


def _finding_text(finding: dict[str, object]) -> str:
    return " ".join(
        str(finding.get(key, ""))
        for key in ("detector", "category", "url", "parameter", "evidence", "recommendation")
    )


def _compact_cluster(cluster: dict[str, object]) -> dict[str, object]:
    members = list(cluster.get("members", []))
    return {
        "cluster_id": cluster["cluster_id"],
        "title": cluster["title"],
        "severity": cluster["severity"],
        "count": cluster["count"],
        "max_similarity": cluster["max_similarity"],
        "sample_urls": [member.get("url") for member in members[:5] if isinstance(member, dict)],
    }
