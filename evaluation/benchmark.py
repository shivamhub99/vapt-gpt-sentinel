"""
Academic Benchmark Runner & Artifact Generator for VAPT-GPT Sentinel (Phase 9).
Executes comparative experiments against baselines, computes research metrics,
and generates publication-quality CSV datasets and matplotlib evaluation figures.
"""

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib

matplotlib.use("Agg")  # Non-interactive headless backend for automated script execution
import matplotlib.pyplot as plt

from evaluation.baselines import StrategyResult, baseline_comparator
from evaluation.metrics import EvaluationMetrics, metrics_calculator
from sentinel.agents.simulation import simulation_orchestrator
from sentinel.core.database import db
from sentinel.core.schemas import Finding, Patch, Verification
from sentinel.core.settings import settings
from sentinel.reasoning.prioritizer import prioritizer
from sentinel.twin.attack_paths import attack_path_analyzer
from sentinel.twin.builder import twin_builder
from sentinel.twin.risk import system_risk_calculator


class BenchmarkRunner:
    """Executes controlled empirical evaluations and exports academic artifacts."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or Path(settings.workspace_dir) / "evaluation" / "results"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _load_empirical_data(self) -> tuple[List[Finding], List[Patch], List[Verification]]:
        """Loads findings, patches, and verification records from database."""
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM findings")
        f_rows = cursor.fetchall()
        cursor.execute("SELECT id FROM patches")
        p_rows = cursor.fetchall()
        cursor.execute("SELECT patch_id FROM verifications")
        v_rows = cursor.fetchall()
        conn.close()

        findings = [db.get_finding(r["id"]) for r in f_rows if db.get_finding(r["id"])]
        patches = [db.get_patch(r["id"]) for r in p_rows if db.get_patch(r["id"])]
        verifications = [
            db.get_verification(r["patch_id"]) for r in v_rows if db.get_verification(r["patch_id"])
        ]
        return findings, patches, verifications

    def export_csv_datasets(
        self,
        strategy_results: List[StrategyResult],
        ranked_findings: List[Finding],
        metrics: EvaluationMetrics,
    ) -> Dict[str, Path]:
        """Saves tabular research datasets as CSV files."""
        csv_paths = {}

        # 1. Benchmark Comparison CSV
        bench_csv = self.output_dir / "benchmark_comparison.csv"
        with open(bench_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Strategy",
                    "Patches_Applied",
                    "Operational_Cost",
                    "Initial_Risk",
                    "Residual_Risk",
                    "Risk_Reduction_Pct",
                    "Efficiency_Ratio",
                    "Paths_Disrupted",
                    "Paths_Remaining",
                ]
            )
            for s in strategy_results:
                writer.writerow(
                    [
                        s.strategy_name,
                        s.patches_applied,
                        s.operational_cost,
                        s.initial_risk,
                        s.residual_risk,
                        s.risk_reduction_pct,
                        s.efficiency_ratio,
                        s.attack_paths_disrupted,
                        s.attack_paths_remaining,
                    ]
                )
        csv_paths["benchmark_csv"] = bench_csv

        # 2. RQ1 Prioritization Comparison CSV
        rq1_csv = self.output_dir / "rq1_prioritization_comparison.csv"
        with open(rq1_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Finding_ID",
                    "CWE",
                    "Title",
                    "Severity",
                    "CVSS_Base",
                    "Contextual_Score",
                    "Location",
                    "Status",
                ]
            )
            for finding in ranked_findings:
                writer.writerow(
                    [
                        finding.id,
                        finding.cwe,
                        finding.title,
                        finding.severity.value,
                        finding.cvss or 0.0,
                        finding.contextual_score or 0.0,
                        finding.file or finding.endpoint or "N/A",
                        finding.status.value,
                    ]
                )
        csv_paths["rq1_csv"] = rq1_csv

        # 3. Overall Remediation Metrics CSV
        metrics_csv = self.output_dir / "remediation_verification_metrics.csv"
        with open(metrics_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Metric_Name", "Value", "Unit"])
            writer.writerow(["Total_Findings", metrics.total_findings, "count"])
            writer.writerow(["Remediation_Attempts", metrics.remediation_attempts, "count"])
            writer.writerow(["Verified_Patches", metrics.verified_patches_count, "count"])
            writer.writerow(["Rejected_Patches", metrics.rejected_patches_count, "count"])
            writer.writerow(["Remediation_Success_Rate", metrics.remediation_success_rate, "%"])
            writer.writerow(["Functional_Pass_Rate", metrics.functional_pass_rate, "%"])
            writer.writerow(["Initial_System_Risk", metrics.initial_risk_score, "score_0_100"])
            writer.writerow(["Residual_System_Risk", metrics.residual_risk_score, "score_0_100"])
            writer.writerow(["Risk_Reduction_Percentage", metrics.risk_reduction_pct, "%"])
            writer.writerow(["Rollback_Rate", metrics.rollback_rate, "%"])
            writer.writerow(
                ["Adversary_Displacement_Rate", metrics.adversary_displacement_rate, "%"]
            )
            writer.writerow(["Total_Defensive_Cost", metrics.total_defensive_cost, "units"])
        csv_paths["metrics_csv"] = metrics_csv

        return csv_paths

    def generate_evaluation_figures(
        self,
        strategy_results: List[StrategyResult],
        ranked_findings: List[Finding],
    ) -> Dict[str, Path]:
        """Generates high-resolution academic figures using matplotlib."""
        plot_paths = {}

        plt.style.use(
            "seaborn-v0_8-whitegrid"
            if "seaborn-v0_8-whitegrid" in plt.style.available
            else "default"
        )

        # -------------------------------------------------------------
        # Figure 1: Strategy Comparison (Risk Reduction % vs Efficiency)
        # -------------------------------------------------------------
        fig, ax1 = plt.subplots(figsize=(9, 5))
        names = [s.strategy_name for s in strategy_results]
        reductions = [s.risk_reduction_pct for s in strategy_results]
        efficiencies = [s.efficiency_ratio for s in strategy_results]

        x_indices = range(len(names))
        width = 0.35

        ax1.bar(
            [i - width / 2 for i in x_indices],
            reductions,
            width,
            label="Risk Reduction (%)",
            color="#0284c7",
        )
        ax2 = ax1.twinx()
        ax2.bar(
            [i + width / 2 for i in x_indices],
            efficiencies,
            width,
            label="Efficiency Ratio (DeltaRisk / Cost)",
            color="#10b981",
        )

        ax1.set_xlabel("Triage & Remediation Strategy", fontweight="bold")
        ax1.set_ylabel("Risk Reduction (%)", color="#0284c7", fontweight="bold")
        ax2.set_ylabel("Efficiency Ratio (Points / Cost)", color="#10b981", fontweight="bold")
        ax1.set_xticks(x_indices)
        ax1.set_xticklabels(names, rotation=15, ha="right", fontsize=9)
        ax1.set_ylim(0, 110)

        plt.title(
            "Comparative Performance: Triage & Remediation Strategies",
            fontsize=12,
            fontweight="bold",
            pad=12,
        )
        fig.tight_layout()

        fig1_path = self.output_dir / "strategy_benchmarks.png"
        fig.savefig(fig1_path, dpi=300)
        plt.close(fig)
        plot_paths["fig_strategies"] = fig1_path

        # -------------------------------------------------------------
        # Figure 2: RQ1 CVSS Base Score vs Contextual Risk Score
        # -------------------------------------------------------------
        if ranked_findings:
            fig_rq1, ax_rq1 = plt.subplots(figsize=(10, 5))
            f_ids = [f.id[:14] for f in ranked_findings]
            cvss_scores = [(f.cvss or 0.0) * 10.0 for f in ranked_findings]
            ctx_scores = [f.contextual_score or 0.0 for f in ranked_findings]

            bar_w = 0.35
            idx = range(len(f_ids))

            ax_rq1.bar(
                [i - bar_w / 2 for i in idx],
                cvss_scores,
                bar_w,
                label="CVSS Base Score (×10)",
                color="#94a3b8",
            )
            ax_rq1.bar(
                [i + bar_w / 2 for i in idx],
                ctx_scores,
                bar_w,
                label="Contextual Risk Score (RQ1)",
                color="#ef4444",
            )

            ax_rq1.set_xlabel("Vulnerability Finding", fontweight="bold")
            ax_rq1.set_ylabel("Normalized Threat Score (0 - 100)", fontweight="bold")
            ax_rq1.set_xticks(idx)
            ax_rq1.set_xticklabels(f_ids, rotation=20, ha="right", fontsize=9)
            ax_rq1.set_ylim(0, 110)
            ax_rq1.legend(loc="upper right")

            plt.title(
                "Research Question 1: CVSS Baseline vs Contextual Risk Prioritization",
                fontsize=12,
                fontweight="bold",
                pad=12,
            )
            fig_rq1.tight_layout()

            fig2_path = self.output_dir / "rq1_cvss_vs_contextual.png"
            fig_rq1.savefig(fig2_path, dpi=300)
            plt.close(fig_rq1)
            plot_paths["fig_rq1"] = fig2_path

        # -------------------------------------------------------------
        # Figure 3: Attack Path Disruption & Residual Risk
        # -------------------------------------------------------------
        fig_paths, ax_paths = plt.subplots(figsize=(8, 4.5))
        init_risks = [s.initial_risk for s in strategy_results]
        res_risks = [s.residual_risk for s in strategy_results]

        p_idx = range(len(names))
        ax_paths.plot(
            p_idx,
            init_risks,
            marker="o",
            linestyle="--",
            color="#ef4444",
            label="Pre-Intervention Risk",
        )
        ax_paths.plot(
            p_idx,
            res_risks,
            marker="s",
            linestyle="-",
            color="#06b6d4",
            linewidth=2,
            label="Post-Intervention Risk",
        )

        ax_paths.set_xlabel("Evaluation Strategy", fontweight="bold")
        ax_paths.set_ylabel("System Attack Surface Risk Score (0 - 100)", fontweight="bold")
        ax_paths.set_xticks(p_idx)
        ax_paths.set_xticklabels(names, rotation=15, ha="right", fontsize=9)
        ax_paths.set_ylim(0, 100)
        ax_paths.legend(loc="upper right")

        plt.title(
            "Attack Surface Risk Depletion Across Remediation Strategies",
            fontsize=12,
            fontweight="bold",
            pad=12,
        )
        fig_paths.tight_layout()

        fig3_path = self.output_dir / "attack_path_reduction.png"
        fig_paths.savefig(fig3_path, dpi=300)
        plt.close(fig_paths)
        plot_paths["fig_paths"] = fig3_path

        return plot_paths

    def run_benchmark(self, budget: int = 2) -> Dict[str, Any]:
        """Runs the complete benchmark suite, computes metrics, and generates artifacts."""
        findings, patches, verifications = self._load_empirical_data()

        # Build base digital twin
        ranked_findings = prioritizer.rank_findings(findings) if findings else []
        twin = twin_builder.build(ranked_findings)
        initial_paths = attack_path_analyzer.find_all_attack_paths(twin)
        initial_risk = system_risk_calculator.calculate_system_risk(initial_paths)[
            "system_risk_score"
        ]

        # Run multi-agent simulation for adversarial displacement metrics
        sim_result = (
            simulation_orchestrator.simulate(twin, max_rounds=5, seed=42) if findings else None
        )

        # Run comparative strategy evaluations
        strategy_results = baseline_comparator.run_all_baselines(
            findings=ranked_findings,
            base_twin=twin,
            budget=budget,
        )

        residual_risk = strategy_results[-1].residual_risk if strategy_results else 0.0

        # Calculate academic research metrics
        metrics = metrics_calculator.calculate(
            findings=ranked_findings,
            patches=patches,
            verifications=verifications,
            initial_risk=initial_risk,
            residual_risk=residual_risk,
            simulation=sim_result,
        )

        # Export CSV datasets and matplotlib figures
        csv_paths = self.export_csv_datasets(strategy_results, ranked_findings, metrics)
        figure_paths = self.generate_evaluation_figures(strategy_results, ranked_findings)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metrics": metrics,
            "strategy_results": strategy_results,
            "csv_paths": csv_paths,
            "figure_paths": figure_paths,
        }


benchmark_runner = BenchmarkRunner()
