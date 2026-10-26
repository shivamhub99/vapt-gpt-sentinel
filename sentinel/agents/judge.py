"""
Judge Arbiter Agent for Digital Twin Simulation (Phase 7).
Executes turn-based state updates, calculates residual attack risk,
analyzes adversary path displacement, and arbitrates round outcomes.
"""

from typing import Optional

from sentinel.agents.schemas import BlueMove, RedMove, RoundResult
from sentinel.twin.attack_paths import attack_path_analyzer
from sentinel.twin.graph import DigitalTwinGraph
from sentinel.twin.risk import system_risk_calculator


class JudgeAgent:
    """Impartial arbiter scoring agent moves and monitoring attack path displacement."""

    def __init__(self, name: str = "Judge_Arbiter"):
        self.name = name

    def apply_defense(self, twin: DigitalTwinGraph, blue_move: BlueMove) -> None:
        """Applies Blue's defensive countermeasure to the active twin graph state."""
        g = twin.graph

        if blue_move.action_type == "PATCH_FINDING":
            # Remove all exploit edges associated with this finding
            edges_to_remove = [
                (u, v) for u, v, d in g.edges(data=True) if d.get("finding_id") == blue_move.target
            ]
            for u, v in edges_to_remove:
                g.remove_edge(u, v)

        elif blue_move.action_type == "REQUIRE_AUTH":
            # Attenuate reachability in-edges
            for u, v, d in list(g.in_edges(blue_move.target, data=True)):
                g[u][v]["probability"] = round(d.get("probability", 1.0) * 0.15, 3)

        elif blue_move.action_type == "ISOLATE_NODE":
            # Remove all in-edges to the isolated asset
            for u, v in list(g.in_edges(blue_move.target)):
                g.remove_edge(u, v)

    def evaluate_round(
        self,
        twin: DigitalTwinGraph,
        round_number: int,
        pre_risk: float,
        red_move: Optional[RedMove],
        blue_move: Optional[BlueMove],
    ) -> RoundResult:
        """
        Executes Blue's defense on the graph, recalibrates system risk,
        checks for adversary displacement, and formats round arbitration.
        """
        if blue_move:
            self.apply_defense(twin, blue_move)

        # Recalculate post-move graph metrics
        post_paths = attack_path_analyzer.find_all_attack_paths(twin)
        post_risk_data = system_risk_calculator.calculate_system_risk(post_paths)
        post_risk = post_risk_data["system_risk_score"]
        risk_delta = round(pre_risk - post_risk, 2)

        # Detect Path Displacement: Did Red's previous target get neutralized,
        # forcing the attacker to displace towards a secondary crown jewel?
        path_displaced = False
        displaced_to: Optional[str] = None

        if red_move and post_paths:
            new_top_target = post_paths[0].target_crown_jewel
            if new_top_target != red_move.targeted_crown_jewel:
                path_displaced = True
                displaced_to = new_top_target

        # Construct Judge narrative
        if not red_move:
            judge_narrative = (
                f"Round {round_number}: Zero viable attack paths exist. System fully contained."
            )
        elif blue_move:
            displacement_note = (
                f" [Adversary displaced to secondary asset '{displaced_to}']"
                if path_displaced
                else ""
            )
            judge_narrative = (
                f"Round {round_number}: Blue deployed '{blue_move.action_type}' on '{blue_move.target}'. "
                f"System risk dropped from {pre_risk} to {post_risk} (Delta: -{risk_delta}). "
                f"Active paths remaining: {len(post_paths)}.{displacement_note}"
            )
        else:
            judge_narrative = (
                f"Round {round_number}: Red advanced unopposed. System risk remains {post_risk}."
            )

        return RoundResult(
            round_number=round_number,
            red_move=red_move,
            blue_move=blue_move,
            pre_round_risk=pre_risk,
            post_round_risk=post_risk,
            risk_delta=risk_delta,
            paths_remaining=len(post_paths),
            path_displaced=path_displaced,
            displaced_to=displaced_to,
            judge_narrative=judge_narrative,
        )


judge_agent = JudgeAgent()
