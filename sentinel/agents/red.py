"""
Red Adversarial Agent for Digital Twin Simulation (Phase 7).
Operates purely in-memory on the Digital Twin graph (0 network traffic).
Identifies the optimal adversarial attack vector by maximizing attack utility:
Utility(path) = (Probability * TargetCriticality) / max(0.5, Cost)
"""

from typing import List, Optional

from sentinel.agents.schemas import RedMove
from sentinel.twin.attack_paths import AttackPath, attack_path_analyzer
from sentinel.twin.graph import DigitalTwinGraph


class RedAgent:
    """Simulates an intelligent threat actor choosing optimal attack trajectories on the twin."""

    def __init__(self, name: str = "Red_Adversary"):
        self.name = name

    def compute_utility(self, path: AttackPath) -> float:
        """
        Calculates attack utility: higher probability and higher crown jewel impact
        yield greater utility; higher cost diminishes utility.
        """
        effective_cost = max(0.5, path.attacker_cost)
        utility = (path.probability * path.target_criticality * 10.0) / effective_cost
        return round(utility, 4)

    def select_move(self, twin: DigitalTwinGraph) -> Optional[RedMove]:
        """
        Analyzes all active attack paths in the twin graph and selects the move
        yielding maximum adversarial utility.
        """
        paths: List[AttackPath] = attack_path_analyzer.find_all_attack_paths(twin)
        if not paths:
            return None

        # Score paths by attack utility
        scored_paths = [(p, self.compute_utility(p)) for p in paths]
        scored_paths.sort(key=lambda item: item[1], reverse=True)

        best_path, best_utility = scored_paths[0]
        primary_finding = best_path.exploited_findings[0] if best_path.exploited_findings else None

        narrative = (
            f"Adversary targets crown jewel '{best_path.target_crown_jewel}' "
            f"(Criticality={best_path.target_criticality:.2f}) via {best_path.description} "
            f"[Probability={best_path.probability:.3f}, Attacker Effort={best_path.attacker_cost:.1f}, "
            f"Utility={best_utility:.3f}]."
        )

        return RedMove(
            path_id=best_path.path_id,
            targeted_crown_jewel=best_path.target_crown_jewel,
            target_criticality=best_path.target_criticality,
            path_probability=best_path.probability,
            attacker_cost=best_path.attacker_cost,
            attack_utility=best_utility,
            exploited_finding=primary_finding,
            narrative=narrative,
        )


red_agent = RedAgent()
