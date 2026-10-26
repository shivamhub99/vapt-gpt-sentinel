"""
Unit and Integration Tests for Phase 9: Evaluation Harness & Academic Artifacts.
Validates:
1. Academic evaluation metrics computation (RSR, FPR, ARR, Rollback Rate).
2. Comparative baseline executions (Scanner-Only, CVSS-Only, Patch-Everything, VAPT-Sentinel).
3. Tabular CSV datasets export.
4. Publication-ready matplotlib evaluation figures export.
5. Typer CLI command 'sentinel evaluate'.
"""

from pathlib import Path
from typing import List

import pytest
from typer.testing import CliRunner

from evaluation.baselines import StrategyResult, baseline_comparator
from evaluation.benchmark import BenchmarkRunner
from evaluation.metrics import EvaluationMetrics, metrics_calculator
from sentinel.agents.schemas import RoundResult, SimulationResult
from sentinel.cli import app
from sentinel.core.schemas import DecisionEnum, Finding, Patch, Severity, Verification
from sentinel.twin.builder import twin_builder
from sentinel.twin.graph import DigitalTwinGraph


@pytest.fixture
def eval_findings() -> List[Finding]:
    return [
        Finding(
            id="eval_sqli_01",
            tool="bandit",
            cwe="CWE-89",
            title="SQL Injection in search API",
            severity=Severity.HIGH,
            cvss=8.8,
            epss=0.45,
            file="app.py",
            endpoint="/api/search",
        ),
        Finding(
            id="eval_idor_01",
            tool="semgrep",
            cwe="CWE-639",
            title="IDOR on Orders Endpoint",
            severity=Severity.HIGH,
            cvss=7.5,
            epss=0.35,
            file="app.py",
            endpoint="/api/orders/<id>",
        ),
        Finding(
            id="eval_secret_01",
            tool="gitleaks",
            cwe="CWE-798",
            title="Hardcoded API Secret",
            severity=Severity.CRITICAL,
            cvss=9.0,
            epss=0.55,
            file="app.py",
        ),
    ]


@pytest.fixture
def eval_twin(eval_findings: List[Finding]) -> DigitalTwinGraph:
    return twin_builder.build(eval_findings)


def test_metrics_calculator_bounds_and_formulas(eval_findings: List[Finding]):
    """Verifies that academic metrics adhere strictly to mathematical definitions and bounds."""
    patches = [
        Patch(
            id="p1",
            finding_id="eval_sqli_01",
            diff="diff1",
            branch="b1",
            rationale="test patch 1",
            attempt=1,
        ),
        Patch(
            id="p2",
            finding_id="eval_idor_01",
            diff="diff2",
            branch="b2",
            rationale="test patch 2",
            attempt=1,
        ),
        Patch(
            id="p3",
            finding_id="eval_secret_01",
            diff="diff3",
            branch="b3",
            rationale="test patch 3",
            attempt=1,
        ),
    ]

    verifications = [
        Verification(
            patch_id="p1",
            finding_id="eval_sqli_01",
            unit_passed=True,
            regression_passed=True,
            original_finding_gone=True,
            decision=DecisionEnum.VERIFIED,
        ),
        Verification(
            patch_id="p2",
            finding_id="eval_idor_01",
            unit_passed=True,
            regression_passed=True,
            original_finding_gone=True,
            decision=DecisionEnum.VERIFIED,
        ),
        Verification(
            patch_id="p3",
            finding_id="eval_secret_01",
            unit_passed=False,
            regression_passed=True,
            original_finding_gone=True,
            decision=DecisionEnum.REJECTED_FUNCTIONAL,
        ),
    ]

    sim = SimulationResult(
        simulation_id="sim_eval",
        seed=42,
        max_rounds=2,
        initial_risk_score=60.0,
        final_risk_score=10.0,
        total_risk_reduction_pct=83.3,
        total_blue_cost=2.0,
        rounds=[
            RoundResult(
                round_number=1,
                pre_round_risk=60.0,
                post_round_risk=25.0,
                risk_delta=35.0,
                paths_remaining=2,
                path_displaced=True,
                displaced_to="orders_ledger",
            ),
            RoundResult(
                round_number=2,
                pre_round_risk=25.0,
                post_round_risk=10.0,
                risk_delta=15.0,
                paths_remaining=0,
                path_displaced=False,
            ),
        ],
        winner="BLUE",
    )

    metrics: EvaluationMetrics = metrics_calculator.calculate(
        findings=eval_findings,
        patches=patches,
        verifications=verifications,
        initial_risk=60.0,
        residual_risk=10.0,
        simulation=sim,
    )

    assert metrics.total_findings == 3
    assert metrics.remediation_attempts == 3
    assert metrics.verified_patches_count == 2
    assert metrics.rejected_patches_count == 1

    # RSR = 2/3 = 66.67%
    assert 66.0 <= metrics.remediation_success_rate <= 67.0
    # FPR = 2/3 = 66.67%
    assert 66.0 <= metrics.functional_pass_rate <= 67.0
    # Risk Reduction = (60 - 10) / 60 = 83.33%
    assert 83.0 <= metrics.risk_reduction_pct <= 84.0
    # Rollback Rate = 100%
    assert metrics.rollback_rate == 100.0
    # Adversary Displacement Rate = 1 out of 2 rounds = 50.0%
    assert metrics.adversary_displacement_rate == 50.0


def test_baseline_comparator_all_strategies(
    eval_findings: List[Finding], eval_twin: DigitalTwinGraph
):
    """Verifies that all 4 triage and remediation baselines execute and compute valid metrics."""
    results: List[StrategyResult] = baseline_comparator.run_all_baselines(
        findings=eval_findings,
        base_twin=eval_twin,
        budget=2,
    )

    assert len(results) == 4
    strategy_names = [r.strategy_name for r in results]
    assert "Scanner-Only" in strategy_names
    assert "CVSS-Only Baseline" in strategy_names
    assert "Patch-Everything" in strategy_names
    assert "VAPT-Sentinel (Proposed)" in strategy_names

    for r in results:
        assert 0.0 <= r.initial_risk <= 100.0
        assert 0.0 <= r.residual_risk <= r.initial_risk
        assert 0.0 <= r.risk_reduction_pct <= 100.0
        assert r.operational_cost >= 0.0
        assert r.efficiency_ratio >= 0.0
        assert r.attack_paths_disrupted >= 0
        assert r.attack_paths_remaining >= 0


def test_benchmark_runner_exports_csv_and_figures(tmp_path: Path):
    """Verifies that BenchmarkRunner exports CSV datasets and matplotlib evaluation figures."""
    runner = BenchmarkRunner(output_dir=tmp_path)
    result = runner.run_benchmark(budget=2)

    assert "metrics" in result
    assert "strategy_results" in result
    assert "csv_paths" in result
    assert "figure_paths" in result

    # Check CSV exports
    csvs = result["csv_paths"]
    for _csv_key, p in csvs.items():
        assert p.exists()
        assert p.stat().st_size > 50

    # Check Figure exports
    figs = result["figure_paths"]
    assert "fig_strategies" in figs
    assert "fig_rq1" in figs
    assert "fig_paths" in figs

    for _fig_key, p in figs.items():
        assert p.exists()
        assert p.stat().st_size > 1000  # PNG must have valid image byte content


def test_cli_evaluate_command(tmp_path: Path):
    """Verifies the CLI command 'sentinel evaluate' runs cleanly."""
    runner = CliRunner()
    result = runner.invoke(app, ["evaluate", "--budget", "2", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0
    assert "VAPT-GPT Sentinel Academic Evaluation Harness (Phase 9)" in result.output
    assert "Comparative Evaluation: Triage & Remediation Baselines" in result.output
    assert "Overall Architecture Research Metrics" in result.output
    assert "Academic Artifacts Successfully Generated!" in result.output
