"""
Baseline Comparative Algorithms for Security Triage & Remediation (Phase 9).
Evaluates four distinct triage and remediation strategies against identical targets:
1. Scanner-Only (Naive Severity Order): Fixes vulnerabilities based purely on raw scanner alerts.
2. CVSS-Only (Industry Baseline): Fixes vulnerabilities ordered strictly by CVSS base scores.
3. Patch-Everything (Brute Force): Unprioritized sequential fixing attempting to remediate all findings.
4. VAPT-Sentinel Contextual (Proposed Framework): Contextual multi-factor formula (RQ1)
   and counterfactual minimum defensive cut (RQ3).
"""

from typing import List

from pydantic import BaseModel, Field

from sentinel.core.schemas import Finding
from sentinel.intel.cvss import cvss_lookup
from sentinel.reasoning.prioritizer import prioritizer
from sentinel.twin.attack_paths import attack_path_analyzer
from sentinel.twin.counterfactual import counterfactual_engine
from sentinel.twin.graph import DigitalTwinGraph
from sentinel.twin.risk import system_risk_calculator


class StrategyResult(BaseModel):
    """Comparative outcome metrics for a specific triage and remediation strategy."""

    strategy_name: str
    description: str
    patches_applied: int
    operational_cost: float
    initial_risk: float = Field(ge=0.0, le=100.0)
    residual_risk: float = Field(ge=0.0, le=100.0)
    risk_reduction_pct: float = Field(ge=0.0, le=100.0)
    efficiency_ratio: float = Field(
        ge=0.0, description="Risk reduction points achieved per unit cost"
    )
    attack_paths_disrupted: int
    attack_paths_remaining: int


class BaselineComparator:
    """Executes controlled comparisons between traditional baselines and VAPT-Sentinel."""

    def _apply_patches_to_twin(
        self, twin: DigitalTwinGraph, finding_ids: List[str]
    ) -> DigitalTwinGraph:
        """Removes exploit edges associated with patched findings on an in-memory clone."""
        cloned = twin.clone()
        g = cloned.graph
        edges_to_remove = [
            (u, v) for u, v, d in g.edges(data=True) if d.get("finding_id") in finding_ids
        ]
        for u, v in edges_to_remove:
            g.remove_edge(u, v)
        return cloned

    def evaluate_strategy(
        self,
        strategy_name: str,
        findings_to_patch: List[str],
        operational_cost: float,
        base_twin: DigitalTwinGraph,
        description: str,
    ) -> StrategyResult:
        """Measures system attack surface reduction on cloned twin state."""
        # Initial state
        initial_paths = attack_path_analyzer.find_all_attack_paths(base_twin)
        initial_risk = system_risk_calculator.calculate_system_risk(initial_paths)[
            "system_risk_score"
        ]

        # Mutated state
        mutated_twin = self._apply_patches_to_twin(base_twin, findings_to_patch)
        post_paths = attack_path_analyzer.find_all_attack_paths(mutated_twin)
        post_risk = system_risk_calculator.calculate_system_risk(post_paths)["system_risk_score"]

        risk_delta = max(0.0, initial_risk - post_risk)
        reduction_pct = (risk_delta / initial_risk * 100.0) if initial_risk > 0 else 0.0
        eff_cost = max(0.5, operational_cost)
        efficiency = round(risk_delta / eff_cost, 2)

        return StrategyResult(
            strategy_name=strategy_name,
            description=description,
            patches_applied=len(findings_to_patch),
            operational_cost=round(operational_cost, 1),
            initial_risk=round(initial_risk, 2),
            residual_risk=round(post_risk, 2),
            risk_reduction_pct=round(reduction_pct, 2),
            efficiency_ratio=efficiency,
            attack_paths_disrupted=len(initial_paths) - len(post_paths),
            attack_paths_remaining=len(post_paths),
        )

    def run_all_baselines(
        self,
        findings: List[Finding],
        base_twin: DigitalTwinGraph,
        budget: int = 2,
    ) -> List[StrategyResult]:
        """
        Runs all 4 comparison strategies with an identical intervention budget.
        """
        results: List[StrategyResult] = []

        if not findings:
            return results

        # 1. SCANNER-ONLY (Order by arrival / raw severity)
        scanner_order = sorted(
            findings,
            key=lambda f: (
                0 if f.severity.value == "CRITICAL" else (1 if f.severity.value == "HIGH" else 2),
                f.id,
            ),
        )
        scanner_selected = [f.id for f in scanner_order[:budget]]
        results.append(
            self.evaluate_strategy(
                strategy_name="Scanner-Only",
                findings_to_patch=scanner_selected,
                operational_cost=len(scanner_selected) * 1.0,
                base_twin=base_twin,
                description=f"Patches top {budget} findings sorted by raw scanner severity without exposure context.",
            )
        )

        # 2. CVSS-ONLY (Order strictly by CVSS descending)
        cvss_order = sorted(
            findings,
            key=lambda f: (f.cvss or cvss_lookup.get_cvss_score(cwe=f.cwe), f.id),
            reverse=True,
        )
        cvss_selected = [f.id for f in cvss_order[:budget]]
        results.append(
            self.evaluate_strategy(
                strategy_name="CVSS-Only Baseline",
                findings_to_patch=cvss_selected,
                operational_cost=len(cvss_selected) * 1.0,
                base_twin=base_twin,
                description=f"Patches top {budget} findings sorted strictly by standard CVSS v3.1 base score.",
            )
        )

        # 3. PATCH-EVERYTHING (Brute force attempt to remediate all findings)
        all_selected = [f.id for f in findings]
        results.append(
            self.evaluate_strategy(
                strategy_name="Patch-Everything",
                findings_to_patch=all_selected,
                operational_cost=len(all_selected) * 1.0,
                base_twin=base_twin,
                description="Attempts to patch all discovered findings sequentially regardless of asset impact.",
            )
        )

        # 4. VAPT-SENTINEL (Contextual Prioritization RQ1 + Counterfactual Cut RQ3)
        cf_cut = counterfactual_engine.evaluate_minimum_defensive_change(
            base_twin, target_reduction_pct=30.0
        )
        sentinel_selected = [
            act.target_id
            for act in cf_cut.recommended_interventions
            if act.action_type == "PATCH_FINDING"
        ]
        # If counterfactual found 0 patch interventions, fallback to top contextual ranked
        if not sentinel_selected:
            ranked = prioritizer.rank_findings(findings)
            sentinel_selected = [f.id for f in ranked[:budget]]

        results.append(
            self.evaluate_strategy(
                strategy_name="VAPT-Sentinel (Proposed)",
                findings_to_patch=sentinel_selected,
                operational_cost=max(
                    1.0,
                    cf_cut.total_cost if cf_cut.total_cost > 0 else len(sentinel_selected) * 1.0,
                ),
                base_twin=base_twin,
                description="Contextual multi-factor prioritization (RQ1) + minimum defensive counterfactual cut (RQ3).",
            )
        )

        return results


baseline_comparator = BaselineComparator()
