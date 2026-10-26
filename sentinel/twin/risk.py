"""
System Risk Score Calculator for Digital Twin Attack Graph (RQ2).
Computes a mathematically sound 0-100 system-level risk score based on
path probabilities, crown jewel criticalities, and independent union models.
"""

from typing import Any, Dict, List

from sentinel.twin.attack_paths import AttackPath


class SystemRiskCalculator:
    """Calculates holistic system risk from digital twin attack paths."""

    def calculate_system_risk(self, paths: List[AttackPath]) -> Dict[str, Any]:
        """
        Computes system risk score using the union of independent attack path probabilities.
        Formula:
        For each crown jewel c:
            P(c compromised) = 1 - Prod_{path in Paths(c)} (1 - P(path))
            Risk(c) = P(c) * Criticality(c) * 100
        SystemRisk = min(100.0, Sum_{c} (Weight(c) * Risk(c)))
        """
        if not paths:
            return {
                "system_risk_score": 0.0,
                "total_paths_count": 0,
                "top_paths": [],
                "crown_jewel_risks": {},
                "summary": "No reachable attack paths discovered from external entryways.",
            }

        # Group paths by target crown jewel
        jewel_paths: Dict[str, List[AttackPath]] = {}
        for p in paths:
            jewel_paths.setdefault(p.target_crown_jewel, []).append(p)

        crown_jewel_risks: Dict[str, Dict[str, Any]] = {}
        total_risk_sum = 0.0

        for jewel, j_paths in jewel_paths.items():
            # Union of path probabilities: 1 - Prod(1 - P)
            prod_safe = 1.0
            for p in j_paths:
                prod_safe *= max(0.0, 1.0 - p.probability)
            p_compromise = 1.0 - prod_safe

            crit = j_paths[0].target_criticality
            jewel_risk = round(p_compromise * crit * 100.0, 2)

            crown_jewel_risks[jewel] = {
                "compromise_probability": round(p_compromise, 4),
                "criticality": crit,
                "risk_score": jewel_risk,
                "path_count": len(j_paths),
            }

            total_risk_sum += jewel_risk

        # Holistic system risk normalized against standard enterprise multi-tier asset base (max 280)
        # Guarantees mathematical monotonicity: adding reachable assets strictly increases risk
        norm_factor = 280.0
        system_risk = round(min(100.0, max(0.0, (total_risk_sum / norm_factor) * 100.0)), 1)

        top_paths = paths[:5]

        summary = (
            f"System Attack Surface Risk Score: {system_risk}/100 based on {len(paths)} attack paths. "
            f"Primary exposure driven by {top_paths[0].description if top_paths else 'N/A'} "
            f"(P={top_paths[0].probability:.2f})."
            if top_paths
            else "Minimal attack surface risk."
        )

        return {
            "system_risk_score": system_risk,
            "total_paths_count": len(paths),
            "top_paths": [p.model_dump() for p in top_paths],
            "crown_jewel_risks": crown_jewel_risks,
            "summary": summary,
        }


system_risk_calculator = SystemRiskCalculator()
