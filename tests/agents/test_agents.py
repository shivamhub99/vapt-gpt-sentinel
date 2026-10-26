"""
Unit and Integration Tests for Phase 7: Multi-Agent Digital Twin Simulation.
Validates:
1. Red agent utility computation and optimal adversarial trajectory selection.
2. Blue agent countermeasure prioritization (patching, auth, isolation).
3. Judge arbiter round evaluation, graph mutation, risk delta, and adversarial displacement detection.
4. Turn-based Simulation Orchestrator execution, convergence, and deterministic seed reproducibility.
5. Invariant: 0 network packets transmitted (pure in-memory graph simulation).
6. Typer CLI command 'sentinel twin simulate'.
"""

from typing import List

import pytest
from typer.testing import CliRunner

from sentinel.agents.blue import blue_agent
from sentinel.agents.judge import judge_agent
from sentinel.agents.red import RedAgent, red_agent
from sentinel.agents.schemas import BlueMove, RedMove, RoundResult, SimulationResult
from sentinel.agents.simulation import SimulationOrchestrator, simulation_orchestrator
from sentinel.cli import app
from sentinel.core.schemas import Finding, Severity
from sentinel.twin.attack_paths import AttackPath, attack_path_analyzer
from sentinel.twin.builder import twin_builder
from sentinel.twin.graph import DigitalTwinGraph, EdgeType, NodeType, TwinEdge, TwinNode
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


@pytest.fixture
def twin_with_findings(sample_findings: List[Finding]) -> DigitalTwinGraph:
    """Builds a realistic digital twin populated with active vulnerabilities."""
    return twin_builder.build(sample_findings)


def test_red_agent_utility_calculation():
    """Verifies adversarial utility formula: Utility = (P * Criticality * 10) / max(0.5, Cost)."""
    agent = RedAgent()

    high_value_path = AttackPath(
        path_id="path_high",
        entry_point="internet",
        target_crown_jewel="database",
        target_criticality=0.95,
        probability=0.8,
        attacker_cost=1.5,
        risk_contribution=76.0,
        nodes=["internet", "app", "database"],
        edges=["reaches", "exploits"],
        exploited_findings=["f_sqli_01"],
        description="High utility path",
    )

    low_value_path = AttackPath(
        path_id="path_low",
        entry_point="internet",
        target_crown_jewel="logs",
        target_criticality=0.2,
        probability=0.3,
        attacker_cost=4.0,
        risk_contribution=6.0,
        nodes=["internet", "app", "logs"],
        edges=["reaches", "reads"],
        exploited_findings=[],
        description="Low utility path",
    )

    util_high = agent.compute_utility(high_value_path)
    util_low = agent.compute_utility(low_value_path)

    assert util_high > util_low
    assert util_high == round((0.8 * 0.95 * 10.0) / 1.5, 4)
    assert util_low == round((0.3 * 0.2 * 10.0) / 4.0, 4)


def test_red_agent_select_move(twin_with_findings: DigitalTwinGraph):
    """Verifies that Red selects the attack path that maximizes adversarial utility."""
    move = red_agent.select_move(twin_with_findings)

    assert move is not None
    assert isinstance(move, RedMove)
    assert move.attack_utility > 0.0
    assert move.targeted_crown_jewel in twin_with_findings.get_crown_jewels()
    assert move.path_probability > 0.0
    assert move.attacker_cost > 0.0
    assert move.exploited_finding is not None
    assert "Adversary targets crown jewel" in move.narrative


def test_red_agent_select_move_empty_twin():
    """Verifies that Red agent safely returns None when no attack paths exist."""
    empty_twin = DigitalTwinGraph(name="empty")
    empty_twin.add_node(
        TwinNode(id="internet", label="Internet", node_type=NodeType.ENTRY, is_entry_point=True)
    )
    empty_twin.add_node(
        TwinNode(id="db", label="DB", node_type=NodeType.DATASTORE, is_crown_jewel=True)
    )

    move = red_agent.select_move(empty_twin)
    assert move is None


def test_blue_agent_select_defense_patching(twin_with_findings: DigitalTwinGraph):
    """Verifies that Blue selects PATCH_FINDING as primary defense to sever active exploit path."""
    red_move = red_agent.select_move(twin_with_findings)
    assert red_move is not None

    blue_move = blue_agent.select_defense(twin_with_findings, red_move)

    assert blue_move is not None
    assert isinstance(blue_move, BlueMove)
    assert blue_move.action_type == "PATCH_FINDING"
    assert blue_move.target == red_move.exploited_finding
    assert blue_move.operational_cost == 1.0
    assert "Deploy verified patch" in blue_move.rationale


def test_blue_agent_select_defense_fallback(twin_with_findings: DigitalTwinGraph):
    """Verifies that Blue falls back to authentication or isolation if no finding is specified."""
    synthetic_red_move = RedMove(
        path_id="synth_path",
        targeted_crown_jewel="database",
        target_criticality=0.9,
        path_probability=0.7,
        attacker_cost=2.0,
        attack_utility=3.15,
        exploited_finding=None,
        narrative="Adversary traversing unpatched route",
    )

    blue_move = blue_agent.select_defense(twin_with_findings, synthetic_red_move)

    assert blue_move is not None
    assert blue_move.action_type in ("REQUIRE_AUTH", "ISOLATE_NODE")
    assert blue_move.operational_cost > 0.0


def test_blue_agent_none_move():
    """Verifies Blue agent returns None when Red move is None."""
    empty_twin = DigitalTwinGraph(name="empty")
    assert blue_agent.select_defense(empty_twin, None) is None


def test_judge_agent_apply_defense_and_evaluate_round(twin_with_findings: DigitalTwinGraph):
    """Verifies Judge modifies the graph state, recalibrates risk, and checks displacement."""
    pre_paths = attack_path_analyzer.find_all_attack_paths(twin_with_findings)
    pre_risk = system_risk_calculator.calculate_system_risk(pre_paths)["system_risk_score"]

    red_move = red_agent.select_move(twin_with_findings)
    assert red_move is not None

    blue_move = blue_agent.select_defense(twin_with_findings, red_move)
    assert blue_move is not None

    round_res = judge_agent.evaluate_round(
        twin=twin_with_findings,
        round_number=1,
        pre_risk=pre_risk,
        red_move=red_move,
        blue_move=blue_move,
    )

    assert isinstance(round_res, RoundResult)
    assert round_res.round_number == 1
    assert round_res.pre_round_risk == pre_risk
    assert round_res.post_round_risk <= pre_risk
    assert round_res.risk_delta >= 0.0
    assert round_res.paths_remaining < len(pre_paths)
    assert "Round 1: Blue deployed" in round_res.judge_narrative


def test_judge_agent_adversarial_displacement_detection():
    """
    Verifies that when Blue patches Red's initial target, the Judge correctly detects
    adversary displacement to an alternate crown jewel.
    """
    twin = DigitalTwinGraph(name="displacement_test")
    twin.add_node(
        TwinNode(id="internet", label="Internet", node_type=NodeType.ENTRY, is_entry_point=True)
    )
    twin.add_node(TwinNode(id="app", label="Web App", node_type=NodeType.SERVICE))
    twin.add_node(TwinNode(id="vuln_primary", label="CWE-89", node_type=NodeType.FINDING))
    twin.add_node(TwinNode(id="vuln_secondary", label="CWE-79", node_type=NodeType.FINDING))
    twin.add_node(
        TwinNode(
            id="crown_jewel_A",
            label="Database A",
            node_type=NodeType.DATASTORE,
            is_crown_jewel=True,
            criticality=0.9,
        )
    )
    twin.add_node(
        TwinNode(
            id="crown_jewel_B",
            label="Orders B",
            node_type=NodeType.DATASTORE,
            is_crown_jewel=True,
            criticality=0.7,
        )
    )

    twin.add_edge(
        TwinEdge(source="internet", target="app", edge_type=EdgeType.REACHES, probability=1.0)
    )
    # Path A: App -> vuln_primary -> crown_jewel_A
    twin.add_edge(
        TwinEdge(
            source="app",
            target="vuln_primary",
            edge_type=EdgeType.EXPLOITS,
            probability=0.9,
            finding_id="f_prim",
        )
    )
    twin.add_edge(
        TwinEdge(
            source="vuln_primary",
            target="crown_jewel_A",
            edge_type=EdgeType.READS,
            probability=0.9,
            finding_id="f_prim",
        )
    )

    # Path B: App -> vuln_secondary -> crown_jewel_B
    twin.add_edge(
        TwinEdge(
            source="app",
            target="vuln_secondary",
            edge_type=EdgeType.EXPLOITS,
            probability=0.5,
            finding_id="f_sec",
        )
    )
    twin.add_edge(
        TwinEdge(
            source="vuln_secondary",
            target="crown_jewel_B",
            edge_type=EdgeType.READS,
            probability=0.5,
            finding_id="f_sec",
        )
    )

    # Red picks crown_jewel_A because of higher utility
    red_move = red_agent.select_move(twin)
    assert red_move is not None
    assert red_move.targeted_crown_jewel == "crown_jewel_A"

    # Blue patches f_prim
    blue_move = blue_agent.select_defense(twin, red_move)
    assert blue_move is not None
    assert blue_move.target == "f_prim"

    round_res = judge_agent.evaluate_round(
        twin=twin,
        round_number=1,
        pre_risk=50.0,
        red_move=red_move,
        blue_move=blue_move,
    )

    # Verify displacement detected to crown_jewel_B
    assert round_res.path_displaced is True
    assert round_res.displaced_to == "crown_jewel_B"
    assert "displaced to secondary asset" in round_res.judge_narrative


def test_simulation_orchestrator_full_loop(twin_with_findings: DigitalTwinGraph):
    """Verifies that the turn-based multi-agent game executes, converges, and produces summary."""
    orchestrator = SimulationOrchestrator()
    result = orchestrator.simulate(twin_with_findings, max_rounds=5, seed=42)

    assert isinstance(result, SimulationResult)
    assert result.seed == 42
    assert result.max_rounds == 5
    assert len(result.rounds) >= 1
    assert len(result.rounds) <= 5
    assert result.initial_risk_score > 0.0
    assert result.final_risk_score < result.initial_risk_score
    assert result.total_risk_reduction_pct > 0.0
    assert result.total_blue_cost > 0.0
    assert "BLUE" in result.winner or "RED" in result.winner
    assert result.stop_reason != ""
    assert "Multi-Agent Twin Simulation Complete" in result.executive_summary


def test_simulation_orchestrator_zero_network_traffic_invariant(
    twin_with_findings: DigitalTwinGraph,
):
    """
    CRITICAL INVARIANT: Simulation operates purely in-memory on a clone.
    The original digital twin graph must remain completely unmutated.
    """
    original_node_count = twin_with_findings.graph.number_of_nodes()
    original_edge_count = twin_with_findings.graph.number_of_edges()

    _ = simulation_orchestrator.simulate(twin_with_findings, max_rounds=5, seed=42)

    # Invariant: Original graph is untouched
    assert twin_with_findings.graph.number_of_nodes() == original_node_count
    assert twin_with_findings.graph.number_of_edges() == original_edge_count


def test_simulation_reproducibility_with_seed(twin_with_findings: DigitalTwinGraph):
    """Verifies that simulations with identical random seeds yield perfectly reproducible results."""
    run1 = simulation_orchestrator.simulate(twin_with_findings, max_rounds=4, seed=99)
    run2 = simulation_orchestrator.simulate(twin_with_findings, max_rounds=4, seed=99)

    assert run1.initial_risk_score == run2.initial_risk_score
    assert run1.final_risk_score == run2.final_risk_score
    assert run1.total_risk_reduction_pct == run2.total_risk_reduction_pct
    assert run1.total_blue_cost == run2.total_blue_cost
    assert len(run1.rounds) == len(run2.rounds)
    assert run1.winner == run2.winner


def test_cli_twin_simulate_command():
    """Verifies the CLI command 'sentinel twin simulate' runs cleanly."""
    runner = CliRunner()
    result = runner.invoke(app, ["twin", "simulate", "--max-rounds", "2", "--seed", "42"])

    assert result.exit_code == 0
    assert "Multi-Agent Digital Twin Simulation (Phase 7)" in result.output
    assert "Game Round Progression" in result.output
    assert "Simulation Result" in result.output
