"""Attack Path Correlation Engine for AdaptiveScan.

Builds a directed dependency graph of vulnerabilities and maps chains of exploits
defining multi-hop attack paths.
"""
from __future__ import annotations
import uuid
from backend.detection.base_detector import Finding

# Mappings of vulnerability categories and detector names to downstream exploitation steps.
# e.g., Information disclosure leads to Auth bypass/Weak Auth, which leads to IDOR, which leads to RCE/Data Leak.
CATEGORY_TRANSITIONS = {
    "javascript_intel": {"authentication", "authorization", "exposure"},
    "cloud_exposure": {"authentication", "authorization", "infrastructure"},
    "infrastructure": {"web_app", "api_security"},
    "web_app": {"api_security", "authorization", "business_logic"},
    "api_security": {"authorization", "business_logic"},
    "authentication": {"authorization", "business_logic"},
    "authorization": {"business_logic", "web_app"},
}


class AttackGraphEngine:
    """Builds a directed vulnerability dependency graph and generates attack chains."""

    def __init__(self, findings: list[Finding]):
        self.findings = findings
        self.nodes = {str(getattr(f, "finding_id", None) or uuid.uuid4()): f for f in findings}
        self.edges: list[tuple[str, str]] = []

    def build_graph(self) -> dict[str, object]:
        """Correlate finding nodes and trace all possible exploit path chains."""
        # Clean nodes from missing IDs
        for node_id, f in list(self.nodes.items()):
            # Ensure findings have parent_findings and attack_chain_ids initialized
            if getattr(f, "parent_findings", None) is None:
                f.parent_findings = []
            if getattr(f, "attack_chain_ids", None) is None:
                f.attack_chain_ids = []

        # Connect nodes based on logical transitions
        for id1, f1 in self.nodes.items():
            for id2, f2 in self.nodes.items():
                if id1 == id2:
                    continue
                if self._can_transition(f1, f2):
                    self.edges.append((id1, id2))
                    if id1 not in f2.parent_findings:
                        f2.parent_findings.append(id1)

        # Trace paths
        chains: list[list[str]] = []
        for node_id in self.nodes:
            if not self._has_incoming(node_id):
                self._dfs_trace(node_id, [], chains)

        # Distribute chain IDs back to finding nodes
        for chain_idx, chain in enumerate(chains):
            chain_id = f"AC-{chain_idx + 1:03d}"
            for node_id in chain:
                f = self.nodes[node_id]
                if chain_id not in f.attack_chain_ids:
                    f.attack_chain_ids.append(chain_id)

        # Build attack graph representation
        graph_nodes = []
        for node_id, f in self.nodes.items():
            graph_nodes.append({
                "id": node_id,
                "title": f.title if hasattr(f, "title") else f.detector,
                "category": f.category,
                "severity": f.severity,
                "cvss_score": f.cvss_score or 5.0,
            })

        graph_edges = [{"source": src, "target": dst} for src, dst in self.edges]

        # Calculate compound risk severity
        risk_score = self._calculate_compound_score(chains)

        return {
            "nodes": graph_nodes,
            "edges": graph_edges,
            "chains": [
                {
                    "chain_id": f"AC-{idx + 1:03d}",
                    "steps": [self.nodes[nid].detector for nid in chain],
                    "nodes": chain
                }
                for idx, chain in enumerate(chains)
            ],
            "compound_risk_score": risk_score,
            "compound_severity": "critical" if risk_score >= 8.5 else "high" if risk_score >= 7.0 else "medium" if risk_score >= 4.0 else "low",
        }

    def _can_transition(self, src: Finding, dest: Finding) -> bool:
        """Determines if vulnerability 'src' can be leveraged to reach 'dest'."""
        src_cat = src.category or "generic"
        dest_cat = dest.category or "generic"

        # Case 1: Category relationship
        if dest_cat in CATEGORY_TRANSITIONS.get(src_cat, set()):
            return True

        # Case 2: Specific detector chain (Information Leak -> SQL Injection / Auth Bypass)
        if src.detector in {"cloud_exposure", "advanced_surface"} and dest.detector in {"sqli", "auth_bypass", "idor"}:
            return True

        # Case 3: Authentication bypass or weak credential -> BOLA/IDOR
        if src.detector in {"auth_bypass", "oauth", "api_authz"} and dest.detector in {"idor", "graphql_authz"}:
            return True

        return False

    def _has_incoming(self, node_id: str) -> bool:
        return any(dst == node_id for _, dst in self.edges)

    def _dfs_trace(self, current: str, path: list[str], chains: list[list[str]]):
        path.append(current)
        children = [dst for src, dst in self.edges if src == current]
        if not children:
            chains.append(list(path))
        else:
            for child in children:
                # Prevent cycles
                if child not in path:
                    self._dfs_trace(child, path, chains)
        path.pop()

    def _calculate_compound_score(self, chains: list[list[str]]) -> float:
        """Calculates compound risk score based on path lengths and node weights."""
        if not self.nodes:
            return 0.0
        max_base = max((f.cvss_score or 5.0 for f in self.nodes.values()), default=5.0)
        
        # Paths increase severity risk
        path_multiplier = 1.0 + (len(chains) * 0.05)
        # Cap at 10.0
        return round(min(10.0, max_base * path_multiplier), 1)
