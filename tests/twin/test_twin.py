"""
Unit and Mathematical Invariant Tests for Phase 6: Digital Twin and Counterfactual Engine (RQ2, RQ3).
Validates:
1. NetworkX directed graph topology construction and typing.
2. Crown jewel and entry point discovery.
3. Attack path traversal from entry points to critical assets.
4. Mathematical bounds of path probabilities: P(path) in [0, 1].
5. System-level holistic risk score in [0, 100].
6. Counterfactual Minimum Defensive Change optimization (RQ3).
7. Graph serialization to Mermaid.js and JSON.
"""

from typing import List

import pytest

from sentinel.core.schemas import Finding, Severity
from sentinel.twin.attack_paths import attack_path_analyzer
from sentinel.twin.builder import twin_builder
from sentinel.twin.counterfactual import counterfactual_engine
from sentinel.twin.graph import (
    DigitalTwinGraph,
    EdgeType,
    NodeType,
    TwinEdge,
    TwinNode,
)
from sentinel.twin.risk import system_risk_calculator


@pytest.fixture
def sample_findings() -> List[Finding]:
    """Provides representative security findings covering major attack vectors."""
    return [
        Finding(
            id="f_sqli_01",
            tool="bandit",
            cwe="CWE-89",
            title="SQL Injection in search endpoint",
            severity=Severity.HIGH,
            cvss=8.5,
            epss=0.45,
            file="app.py",
            endpoint="/api/search",
        ),
        Finding(
            id="f_idor_01",
            tool="semgrep",
            cwe="CWE-639",
            title="Insecure Direct Object Reference on Orders",
            severity=Severity.HIGH,
            cvss=7.5,
            epss=0.30,
            file="app.py",
            endpoint="/api/orders/<id>",
        ),
        Finding(
            id="f_secret_01",
            tool="gitleaks",
            cwe="CWE-798",
            title="Hardcoded API Secret Key",
            severity=Severity.CRITICAL,
            cvss=9.0,
            epss=0.55,
            file="app.py",
        ),
    ]


def test_digital_twin_graph_construction(sample_findings: List[Finding]):
    """Verifies that TwinBuilder constructs a valid NetworkX DiGraph with typed nodes and edges."""
    twin = twin_builder.build(sample_findings)

    assert isinstance(twin, DigitalTwinGraph)
    assert twin.graph.number_of_nodes() > 5
    assert twin.graph.number_of_edges() > 5

    # Check entry point
    entries = twin.get_entry_nodes()
    assert "internet" in entries

    # Check crown jewels
    jewels = twin.get_crown_jewels()
    assert "database" in jewels
    assert "orders_ledger" in jewels
    assert "admin_account" in jewels

    # Check node attributes
    db_node = twin.graph.nodes["database"]
    assert db_node["node_type"] == NodeType.DATASTORE.value
    assert db_node["criticality"] >= 0.9
    assert db_node["is_crown_jewel"] is True


def test_twin_graph_mermaid_export(sample_findings: List[Finding]):
    """Verifies Mermaid.js flowchart export for artifact rendering."""
    twin = twin_builder.build(sample_findings)
    mermaid_str = twin.to_mermaid()

    assert mermaid_str.startswith("flowchart LR")
    assert "internet" in mermaid_str
    assert "database" in mermaid_str
    assert "-->" in mermaid_str


def test_twin_graph_dict_serialization(sample_findings: List[Finding]):
    """Verifies JSON-serializable dictionary export of graph topology."""
    twin = twin_builder.build(sample_findings)
    d = twin.to_dict()

    assert "nodes" in d
    assert "edges" in d
    assert d["node_count"] == twin.graph.number_of_nodes()
    assert d["edge_count"] == twin.graph.number_of_edges()


def test_attack_path_discovery_and_probabilities(sample_findings: List[Finding]):
    """
    Research Question 2 (RQ2):
    Verifies that multi-step attack paths from Internet to Crown Jewels
    are enumerated with valid probabilistic calculations.
    """
    twin = twin_builder.build(sample_findings)
    paths = attack_path_analyzer.find_all_attack_paths(twin)

    assert len(paths) >= 2  # SQLi to database, IDOR to orders_ledger, Secret to admin_account

    for p in paths:
        # Probability bound invariant: 0.0 < P <= 1.0
        assert 0.0 < p.probability <= 1.0
        # Attacker cost invariant: Cost > 0
        assert p.attacker_cost > 0.0
        # Target criticality invariant: in [0, 1]
        assert 0.0 <= p.target_criticality <= 1.0
        # Risk contribution invariant: in [0, 100]
        assert 0.0 <= p.risk_contribution <= 100.0
        # Discovered path links entry to target
        assert p.entry_point == "internet"
        assert p.target_crown_jewel in twin.get_crown_jewels()
        assert len(p.exploited_findings) > 0

    # Paths must be sorted descending by risk contribution
    risk_scores = [p.risk_contribution for p in paths]
    assert risk_scores == sorted(risk_scores, reverse=True)


def test_system_risk_score_bounds_and_monotonicity(sample_findings: List[Finding]):
    """
    Research Question 2 (RQ2):
    Verifies that System Risk Score is strictly bounded in [0, 100]
    and monotonically increases with additional attack vectors.
    """
    twin_full = twin_builder.build(sample_findings)
    paths_full = attack_path_analyzer.find_all_attack_paths(twin_full)
    risk_full = system_risk_calculator.calculate_system_risk(paths_full)

    # Invariant: 0.0 <= Risk <= 100.0
    full_score = risk_full["system_risk_score"]
    assert 0.0 <= full_score <= 100.0
    assert risk_full["total_paths_count"] == len(paths_full)
    assert len(risk_full["crown_jewel_risks"]) > 0

    # Monotonicity test: A twin with only 1 finding should have equal or lower risk
    twin_single = twin_builder.build([sample_findings[0]])
    paths_single = attack_path_analyzer.find_all_attack_paths(twin_single)
    risk_single = system_risk_calculator.calculate_system_risk(paths_single)

    assert risk_single["system_risk_score"] <= full_score


def test_counterfactual_minimum_defensive_change_rq3(sample_findings: List[Finding]):
    """
    Research Question 3 (RQ3):
    Verifies that CounterfactualEngine solves the Minimum Defensive Change Problem:
    finds the minimal-cost intervention set that drops system risk below threshold.
    """
    twin = twin_builder.build(sample_findings)
    result = counterfactual_engine.evaluate_minimum_defensive_change(
        twin, target_reduction_pct=30.0
    )

    # Invariants
    assert result.pre_risk_score > 0.0
    assert result.post_risk_score < result.pre_risk_score
    assert result.risk_reduction_pct >= 30.0
    assert result.total_cost > 0.0
    assert len(result.recommended_interventions) > 0
    assert result.disrupted_paths_count >= 0

    # Trade-off alternatives exist
    assert len(result.tradeoff_alternatives) > 0
    assert any(a["disrupted_paths"] > 0 for a in result.tradeoff_alternatives)
    assert "Counterfactual Minimum Defensive Solution" in result.explanation


def test_counterfactual_cutting_critical_bridge_neutralizes_path():
    """
    Validates that applying an intervention that removes an exploit bridge
    completely severs the attack path on an in-memory clone without touching original graph.
    """
    simple_twin = DigitalTwinGraph(name="test_bridge")
    simple_twin.add_node(
        TwinNode(id="internet", label="Internet", node_type=NodeType.ENTRY, is_entry_point=True)
    )
    simple_twin.add_node(TwinNode(id="app", label="Web App", node_type=NodeType.SERVICE))
    simple_twin.add_node(TwinNode(id="sqli", label="CWE-89", node_type=NodeType.FINDING))
    simple_twin.add_node(
        TwinNode(
            id="db", label="DB", node_type=NodeType.DATASTORE, is_crown_jewel=True, criticality=0.9
        )
    )

    simple_twin.add_edge(
        TwinEdge(source="internet", target="app", edge_type=EdgeType.REACHES, probability=1.0)
    )
    simple_twin.add_edge(
        TwinEdge(
            source="app",
            target="sqli",
            edge_type=EdgeType.EXPLOITS,
            probability=0.8,
            finding_id="sqli_1",
        )
    )
    simple_twin.add_edge(
        TwinEdge(
            source="sqli",
            target="db",
            edge_type=EdgeType.READS,
            probability=0.9,
            finding_id="sqli_1",
        )
    )

    # Initial state: 1 attack path exists
    paths_before = attack_path_analyzer.find_all_attack_paths(simple_twin)
    assert len(paths_before) == 1

    # Counterfactual intervention: Patch sqli_1
    candidates = counterfactual_engine.generate_candidate_interventions(simple_twin)
    patch_action = [c for c in candidates if c.target_id == "sqli_1"]
    assert len(patch_action) == 1

    mutated = counterfactual_engine.apply_interventions(simple_twin, patch_action)

    # Post-intervention state: 0 attack paths exist
    paths_after = attack_path_analyzer.find_all_attack_paths(mutated)
    assert len(paths_after) == 0

    # Original twin remains intact
    assert len(attack_path_analyzer.find_all_attack_paths(simple_twin)) == 1
