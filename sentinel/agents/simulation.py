"""
Simulation Orchestrator for Multi-Agent Digital Twin (Phase 7).
Executes turn-based Red/Blue/Judge game rounds purely in-memory (0 network packets).
Bounded to max 5 rounds with deterministic seeds for thesis reproducibility.
"""

import random
from datetime import datetime, timezone
from typing import List

from sentinel.agents.blue import blue_agent
from sentinel.agents.judge import judge_agent
from sentinel.agents.red import red_agent
from sentinel.agents.schemas import RoundResult, SimulationResult
from sentinel.twin.attack_paths import attack_path_analyzer
from sentinel.twin.graph import DigitalTwinGraph
from sentinel.twin.risk import system_risk_calculator


class SimulationOrchestrator:
    """Coordinates turn-based in-memory Red/Blue/Judge multi-agent simulations."""

    def simulate(
        self,
        twin: DigitalTwinGraph,
        max_rounds: int = 5,
        seed: int = 42,
    ) -> SimulationResult:
        """
        Runs an autonomous multi-round game on an in-memory clone of the digital twin.
        Zero network packets are transmitted.
        """
        random.seed(seed)
        sim_twin = twin.clone()
        sim_id = f"sim_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

        # 1. Baseline measurements
        initial_paths = attack_path_analyzer.find_all_attack_paths(sim_twin)
        initial_risk_data = system_risk_calculator.calculate_system_risk(initial_paths)
        initial_risk = initial_risk_data["system_risk_score"]

        rounds: List[RoundResult] = []
        current_risk = initial_risk
        total_blue_cost = 0.0
        converged = False
        stop_reason = ""

        # 2. Turn-based round loop
        for round_idx in range(1, max_rounds + 1):
            # Check if attack paths remain
            curr_paths = attack_path_analyzer.find_all_attack_paths(sim_twin)
            if not curr_paths:
                converged = True
                stop_reason = (
                    "All attack paths neutralized; zero adversarial reachability remaining."
                )
                break

            # A. Red Agent Move
            red_move = red_agent.select_move(sim_twin)
            if not red_move:
                converged = True
                stop_reason = "Adversary exhausted viable attack trajectories."
                break

            # B. Blue Agent Response
            blue_move = blue_agent.select_defense(sim_twin, red_move)
            if blue_move:
                total_blue_cost += blue_move.operational_cost

            # C. Judge Agent Arbitration
            round_outcome = judge_agent.evaluate_round(
                twin=sim_twin,
                round_number=round_idx,
                pre_risk=current_risk,
                red_move=red_move,
                blue_move=blue_move,
            )
            rounds.append(round_outcome)
            current_risk = round_outcome.post_round_risk

            # D. Early Containment Check
            if current_risk <= 5.0 or round_outcome.paths_remaining == 0:
                converged = True
                stop_reason = f"System contained at Round {round_idx} with residual risk <= 5.0."
                break

        if not stop_reason:
            stop_reason = f"Simulation completed max allowed rounds ({max_rounds})."

        # 3. Final summary metrics
        risk_reduction = initial_risk - current_risk
        reduction_pct = (
            round((risk_reduction / initial_risk) * 100.0, 2) if initial_risk > 0 else 0.0
        )

        # Winner determination
        if current_risk <= 5.0 or reduction_pct >= 80.0:
            winner = "BLUE (Defensive Containment)"
        elif reduction_pct >= 40.0:
            winner = "BLUE (Substantial Risk Reduction)"
        else:
            winner = "RED (Adversary Persistent)"

        displacements = sum(1 for r in rounds if r.path_displaced)
        exec_summary = (
            f"Multi-Agent Twin Simulation Complete ({len(rounds)} rounds, seed={seed}): "
            f"Winner: {winner}. Initial risk {initial_risk}/100 was reduced to {current_risk}/100 "
            f"(-{reduction_pct:.1f}% risk reduction) at total defensive cost of {total_blue_cost:.1f}. "
            f"Adversary path displacement occurred {displacements} time(s). {stop_reason}"
        )

        return SimulationResult(
            simulation_id=sim_id,
            seed=seed,
            max_rounds=max_rounds,
            initial_risk_score=initial_risk,
            final_risk_score=current_risk,
            total_risk_reduction_pct=reduction_pct,
            total_blue_cost=round(total_blue_cost, 2),
            rounds=rounds,
            converged=converged,
            winner=winner,
            stop_reason=stop_reason,
            executive_summary=exec_summary,
        )


simulation_orchestrator = SimulationOrchestrator()
