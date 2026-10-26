"""
Counterfactual Reasoning Engine for Minimum Defensive Change (RQ3).
Solves the Minimum Defensive Change Problem:
Finds the minimal-cost defensive intervention set that satisfies a target
risk reduction threshold (or breaks all top attack paths) using in-memory graph mutations.
"""

from itertools import combinations
from typing import Any, Dict, List, Set

from pydantic import BaseModel, Field

from sentinel.twin.attack_paths import attack_path_analyzer
from sentinel.twin.graph import DigitalTwinGraph, NodeType
from sentinel.twin.risk import system_risk_calculator


class Intervention(BaseModel):
    id: str
    action_type: str  # PATCH_FINDING, ISOLATE_ENDPOINT, DEFENSIVE_CONTROL
    target_id: str
    target_label: str
    cost: float = Field(ge=0.1, le=100.0)
    description: str


class CounterfactualResult(BaseModel):
    pre_risk_score: float
    post_risk_score: float
    risk_reduction_pct: float
    total_cost: float
    recommended_interventions: List[Intervention]
    disrupted_paths_count: int
    residual_paths_count: int
    tradeoff_alternatives: List[Dict[str, Any]] = Field(default_factory=list)
    explanation: str = ""


class CounterfactualEngine:
    """Evaluates defensive 'what-if' scenarios to identify the optimal minimal-cost mitigation set."""

    def generate_candidate_interventions(self, twin: DigitalTwinGraph) -> List[Intervention]:
        """Discovers all possible defensive interventions available in the digital twin."""
        candidates: List[Intervention] = []
        g = twin.graph

        # 1. Finding Patch Interventions
        seen_findings: Set[str] = set()
        for _, _, data in g.edges(data=True):
            f_id = data.get("finding_id")
            if f_id and f_id not in seen_findings:
                seen_findings.add(f_id)
                candidates.append(
                    Intervention(
                        id=f"patch_{f_id}",
                        action_type="PATCH_FINDING",
                        target_id=f_id,
                        target_label=f"Patch Finding {f_id}",
                        cost=1.0,
                        description=f"Neutralize exploit edge for vulnerability {f_id} via verified patch.",
                    )
                )

        # 2. Endpoint Protection Interventions
        for n, data in g.nodes(data=True):
            if data.get("node_type") == NodeType.ENDPOINT.value:
                candidates.append(
                    Intervention(
                        id=f"protect_{n}",
                        action_type="REQUIRE_AUTH",
                        target_id=n,
                        target_label=f"Require Strict Auth on {data.get('label', n)}",
                        cost=2.5,
                        description=f"Add authentication check and rate limiting to {n}.",
                    )
                )

        return candidates

    def apply_interventions(
        self, twin: DigitalTwinGraph, interventions: List[Intervention]
    ) -> DigitalTwinGraph:
        """Applies a set of hypothetical interventions to an in-memory graph clone."""
        cloned = twin.clone()
        g = cloned.graph

        for item in interventions:
            if item.action_type == "PATCH_FINDING":
                # Remove all exploit edges associated with this finding
                edges_to_remove = [
                    (u, v)
                    for u, v, d in g.edges(data=True)
                    if d.get("finding_id") == item.target_id
                ]
                for u, v in edges_to_remove:
                    g.remove_edge(u, v)

            elif item.action_type == "REQUIRE_AUTH":
                # Attenuate reachability edge probability to 0.15
                in_edges = list(g.in_edges(item.target_id, data=True))
                for u, v, d in in_edges:
                    g[u][v]["probability"] = round(d.get("probability", 1.0) * 0.15, 3)

        return cloned

    def evaluate_minimum_defensive_change(
        self,
        twin: DigitalTwinGraph,
        target_reduction_pct: float = 40.0,
        max_combination_size: int = 3,
    ) -> CounterfactualResult:
        """
        Solves the Minimum Defensive Change Problem (RQ3):
        min sum(Cost) s.t. RiskReduction >= target_reduction_pct.
        """
        # Baseline analysis
        base_paths = attack_path_analyzer.find_all_attack_paths(twin)
        base_risk_data = system_risk_calculator.calculate_system_risk(base_paths)
        base_risk = base_risk_data["system_risk_score"]

        if base_risk == 0.0 or not base_paths:
            return CounterfactualResult(
                pre_risk_score=0.0,
                post_risk_score=0.0,
                risk_reduction_pct=0.0,
                total_cost=0.0,
                recommended_interventions=[],
                disrupted_paths_count=0,
                residual_paths_count=0,
                explanation="System attack surface already at 0 risk; no interventions required.",
            )

        candidates = self.generate_candidate_interventions(twin)
        valid_plans: List[Dict[str, Any]] = []

        # Evaluate combinations of size 1 up to max_combination_size
        for k in range(1, min(len(candidates) + 1, max_combination_size + 1)):
            for comb in combinations(candidates, k):
                comb_list = list(comb)
                total_cost = sum(i.cost for i in comb_list)

                # Mutate clone and measure residual risk
                mutated = self.apply_interventions(twin, comb_list)
                post_paths = attack_path_analyzer.find_all_attack_paths(mutated)
                post_risk_data = system_risk_calculator.calculate_system_risk(post_paths)
                post_risk = post_risk_data["system_risk_score"]

                risk_reduction = base_risk - post_risk
                reduction_pct = (
                    round((risk_reduction / base_risk) * 100.0, 2) if base_risk > 0 else 0.0
                )
                disrupted = len(base_paths) - len(post_paths)

                plan_record = {
                    "interventions": comb_list,
                    "total_cost": round(total_cost, 2),
                    "post_risk": post_risk,
                    "reduction_pct": reduction_pct,
                    "disrupted_paths": disrupted,
                    "residual_paths": len(post_paths),
                }
                valid_plans.append(plan_record)

        # Filter plans that meet or exceed target_reduction_pct
        qualifying = [p for p in valid_plans if p["reduction_pct"] >= target_reduction_pct]

        if qualifying:
            # Sort by total_cost ascending, then reduction_pct descending (minimal cost first)
            qualifying.sort(key=lambda p: (p["total_cost"], -p["reduction_pct"]))
            optimal_plan = qualifying[0]
        else:
            # Fall back to plan with highest reduction if threshold not fully reachable
            valid_plans.sort(key=lambda p: (-p["reduction_pct"], p["total_cost"]))
            optimal_plan = (
                valid_plans[0]
                if valid_plans
                else {
                    "interventions": [],
                    "total_cost": 0.0,
                    "post_risk": base_risk,
                    "reduction_pct": 0.0,
                    "disrupted_paths": 0,
                    "residual_paths": len(base_paths),
                }
            )

        # Format trade-off alternatives for thesis/dashboard
        tradeoffs = []
        for p in sorted(valid_plans, key=lambda x: x["reduction_pct"], reverse=True)[:5]:
            tradeoffs.append(
                {
                    "actions": ", ".join(i.target_label for i in p["interventions"]),
                    "cost": p["total_cost"],
                    "post_risk": p["post_risk"],
                    "reduction_pct": f"{p['reduction_pct']:.1f}%",
                    "disrupted_paths": p["disrupted_paths"],
                }
            )

        explanation = (
            f"Counterfactual Minimum Defensive Solution (RQ3): Executing {len(optimal_plan['interventions'])} "
            f"action(s) at minimal operational cost {optimal_plan['total_cost']} achieves a "
            f"{optimal_plan['reduction_pct']:.1f}% reduction in system risk (dropping risk from "
            f"{base_risk} to {optimal_plan['post_risk']}), disrupting {optimal_plan['disrupted_paths']} attack path(s)."
        )

        return CounterfactualResult(
            pre_risk_score=base_risk,
            post_risk_score=optimal_plan["post_risk"],
            risk_reduction_pct=optimal_plan["reduction_pct"],
            total_cost=optimal_plan["total_cost"],
            recommended_interventions=optimal_plan["interventions"],
            disrupted_paths_count=optimal_plan["disrupted_paths"],
            residual_paths_count=optimal_plan["residual_paths"],
            tradeoff_alternatives=tradeoffs,
            explanation=explanation,
        )


counterfactual_engine = CounterfactualEngine()
