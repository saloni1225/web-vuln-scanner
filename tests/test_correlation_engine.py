import pytest
from backend.detection.base_detector import Finding
from backend.core.correlation import AttackGraphEngine
from backend.utils.helpers import map_cvss_vector

def test_cvss_vector_mapping():
    # Test vector generation logic for various vulnerabilities
    sqli_vector = map_cvss_vector("sqli", "critical")
    assert "AV:N" in sqli_vector
    assert "PR:N" in sqli_vector
    assert "A:H" in sqli_vector  # High availability impact for SQLi
    
    xss_vector = map_cvss_vector("xss", "medium")
    assert "UI:R" in xss_vector  # Requires User Interaction
    assert "C:L" in xss_vector
    
    csrf_vector = map_cvss_vector("csrf", "high")
    assert "UI:R" in csrf_vector
    assert "PR:N" in csrf_vector
    assert "C:N" in csrf_vector
    assert "I:H" in csrf_vector

def test_attack_graph_correlation():
    # Mock a set of findings representing a multi-hop attack chain:
    # 1. Credentials leaked in JS (javascript_intel)
    # 2. Administrative access endpoint with weak auth (authentication)
    # 3. IDOR / Access Control Bypass (authorization)
    # 4. State changing business logic execution (business_logic)
    
    f1 = Finding(
        detector="secret_exposure",
        severity="medium",
        url="http://target/app.js",
        evidence="API key found: AB12...",
        recommendation="Remove key",
        confidence="high",
        category="javascript_intel",
        cvss_score=5.5
    )
    f1.finding_id = "f1"
    
    f2 = Finding(
        detector="weak_auth",
        severity="high",
        url="http://target/admin/login",
        evidence="Hardcoded user credentials accepted",
        recommendation="Secure authentication",
        confidence="high",
        category="authentication",
        cvss_score=8.1
    )
    f2.finding_id = "f2"
    
    f3 = Finding(
        detector="idor",
        severity="high",
        url="http://target/admin/users/1001",
        evidence="Accessed privileged ID without check",
        recommendation="Implement check",
        confidence="high",
        category="authorization",
        cvss_score=8.5
    )
    f3.finding_id = "f3"

    findings = [f1, f2, f3]
    engine = AttackGraphEngine(findings)
    graph = engine.build_graph()
    
    # Assert nodes and edges were built correctly
    assert len(graph["nodes"]) == 3
    assert len(graph["edges"]) >= 2
    
    # Assert path chains are traced correctly
    assert len(graph["chains"]) > 0
    # Make sure chain IDs got mapped back to the Finding objects
    assert "AC-001" in f1.attack_chain_ids
    assert "AC-001" in f2.attack_chain_ids
    
    # Assert parent relation is saved
    assert "f2" in f3.parent_findings
    assert "f1" in f2.parent_findings
    
    # Assert compound severity calculation increases score
    assert graph["compound_risk_score"] > 8.5
    assert graph["compound_severity"] == "critical"
