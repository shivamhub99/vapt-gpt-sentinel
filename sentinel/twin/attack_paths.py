"""
Attack Path Analysis Engine for VAPT-GPT Sentinel (RQ2).
Enumerate all paths from external entry points to crown jewels,
computing path probability, attacker effort, and risk contributions.
"""

from typing import Any, Dict, List

import networkx as nx
from pydantic import BaseModel, Field

from sentinel.twin.graph import DigitalTwinGraph


class AttackPath(BaseModel):
    """Represents a discovered multi-hop exploit progression from Entry to Crown Jewel."""

    path_id: str
    nodes: List[str]
    entry_point: str
    target_crown_jewel: str
    probability: float = Field(ge=0.0, le=1.0)
    attacker_cost: float = Field(ge=0.0)
    target_criticality: float = Field(ge=0.0, le=1.0)
    risk_contribution: float = Field(ge=0.0, le=100.0)
    exploited_findings: List[str] = Field(default_factory=list)
    description: str = ""
    edge_details: List[Dict[str, Any]] = Field(default_factory=list)


class AttackPathAnalyzer:
    """Discovers and quantifies attack paths across the digital twin graph."""

    def find_all_attack_paths(
        self, twin: DigitalTwinGraph, max_path_length: int = 8
    ) -> List[AttackPath]:
        """
        Discovers all simple paths from Entry points (e.g. Internet) to Crown Jewels.
        Sorts paths by Risk Contribution descending (highest probability & impact first).
        """
        g = twin.graph
        entries = twin.get_entry_nodes()
        crown_jewels = twin.get_crown_jewels()

        paths: List[AttackPath] = []
        path_counter = 1

        for src in entries:
            for dst in crown_jewels:
                if not nx.has_path(g, src, dst):
                    continue

                for node_sequence in nx.all_simple_paths(
                    g, source=src, target=dst, cutoff=max_path_length
                ):
                    # Compute path probability and cost
                    path_prob = 1.0
                    path_cost = 0.0
                    exploited_findings: List[str] = []
                    edge_details: List[Dict[str, Any]] = []

                    for i in range(len(node_sequence) - 1):
                        u = node_sequence[i]
                        v = node_sequence[i + 1]
                        edge_data = g.get_edge_data(u, v) or {}

                        prob = edge_data.get("probability", 1.0)
                        cost = edge_data.get("cost", 1.0)
                        f_id = edge_data.get("finding_id")

                        path_prob *= prob
                        path_cost += cost

                        if f_id and f_id not in exploited_findings:
                            exploited_findings.append(f_id)

                        edge_details.append(
                            {
                                "from": u,
                                "to": v,
                                "edge_type": edge_data.get("edge_type", "reaches"),
                                "probability": prob,
                                "cost": cost,
                                "finding_id": f_id,
                            }
                        )

                    # Compute target impact & risk contribution
                    target_data = g.nodes[dst]
                    target_crit = target_data.get("criticality", 0.8)
                    risk_contrib = round(min(100.0, path_prob * target_crit * 100.0), 2)

                    # Generate human-readable narrative storyline
                    node_labels = [g.nodes[n].get("label", n) for n in node_sequence]
                    narrative = " -> ".join(node_labels)

                    attack_path = AttackPath(
                        path_id=f"path_{path_counter:03d}",
                        nodes=node_sequence,
                        entry_point=src,
                        target_crown_jewel=dst,
                        probability=round(path_prob, 4),
                        attacker_cost=round(path_cost, 2),
                        target_criticality=target_crit,
                        risk_contribution=risk_contrib,
                        exploited_findings=exploited_findings,
                        description=narrative,
                        edge_details=edge_details,
                    )
                    paths.append(attack_path)
                    path_counter += 1

        # Sort by risk contribution descending
        paths.sort(key=lambda p: (p.risk_contribution, p.probability), reverse=True)
        return paths


attack_path_analyzer = AttackPathAnalyzer()
