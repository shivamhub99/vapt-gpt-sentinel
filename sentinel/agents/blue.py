"""
Blue Defensive Agent for Digital Twin Simulation (Phase 7).
Proposes cost-effective defensive interventions to break the adversary's attack trajectory.
Operates purely on graph state with zero network overhead.
"""

from typing import List, Optional

from sentinel.agents.schemas import BlueMove, RedMove
from sentinel.twin.graph import DigitalTwinGraph, NodeType


class BlueAgent:
    """Simulates a defensive security operations agent prioritizing countermeasures."""

    def __init__(self, name: str = "Blue_Defender"):
        self.name = name

    def select_defense(
        self, twin: DigitalTwinGraph, red_move: Optional[RedMove]
    ) -> Optional[BlueMove]:
        """
        Analyzes Red's attack move and selects the most cost-effective defensive countermeasure.
        Priority:
        1. Patching the critical finding on the active path (breaks the exploit bridge).
        2. Adding strict authentication to entry endpoints.
        3. Adding WAF inspection controls.
        """
        if not red_move:
            return None

        candidates: List[BlueMove] = []

        # Option A: Patch the primary exploited vulnerability
        if red_move.exploited_finding:
            candidates.append(
                BlueMove(
                    action_type="PATCH_FINDING",
                    target=red_move.exploited_finding,
                    target_label=f"Patch Finding {red_move.exploited_finding}",
                    operational_cost=1.0,
                    rationale=(
                        f"Deploy verified patch for vulnerability '{red_move.exploited_finding}', "
                        f"severing Red's active attack trajectory to crown jewel '{red_move.targeted_crown_jewel}'."
                    ),
                )
            )

        # Option B: Require strict authentication on endpoints traversed
        g = twin.graph
        for n, data in g.nodes(data=True):
            if data.get("node_type") == NodeType.ENDPOINT.value:
                candidates.append(
                    BlueMove(
                        action_type="REQUIRE_AUTH",
                        target=n,
                        target_label=f"Enforce Authentication on {data.get('label', n)}",
                        operational_cost=2.5,
                        rationale=f"Attenuate external reachability to {n} via token-based access control.",
                    )
                )

        if not candidates:
            # Fallback: Isolate crown jewel service
            candidates.append(
                BlueMove(
                    action_type="ISOLATE_NODE",
                    target=red_move.targeted_crown_jewel,
                    target_label=f"Network Isolation of {red_move.targeted_crown_jewel}",
                    operational_cost=5.0,
                    rationale="Emergency network segment isolation of critical crown jewel.",
                )
            )

        # Select the defense with minimal cost that directly breaks Red's path (Patch first)
        candidates.sort(
            key=lambda m: (0 if m.action_type == "PATCH_FINDING" else 1, m.operational_cost)
        )
        return candidates[0]


blue_agent = BlueAgent()
