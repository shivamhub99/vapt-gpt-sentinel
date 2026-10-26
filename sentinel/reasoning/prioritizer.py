"""
Prioritization Engine for VAPT-GPT Sentinel (Research Question 1 - RQ1).
Implements dual rankers:
1. Baseline CVSS-only ranker (industry standard comparison).
2. Contextual Weighted Formula ranker (CVSS + EPSS + Reachability + Data Sensitivity + Graph Centrality).
Ensures the numeric score is strictly computed by the deterministic mathematical formula,
while the LLM produces the qualitative threat explanation.
"""

from typing import List, Optional, Tuple

from sentinel.core.schemas import ContextFactors, Finding, RiskScore
from sentinel.intel.cvss import cvss_lookup
from sentinel.intel.epss import epss_lookup
from sentinel.reasoning.context import context_engine
from sentinel.reasoning.explainer import threat_explainer

# Sensitivity weight map (0 - 100)
DATA_SENSITIVITY_SCORES = {
    "restricted": 100.0,
    "confidential": 75.0,
    "internal": 40.0,
    "public": 10.0,
}

# Formula component weights (must sum to 1.0)
WEIGHT_CVSS = 0.25
WEIGHT_EPSS = 0.25
WEIGHT_REACHABILITY = 0.25
WEIGHT_SENSITIVITY = 0.15
WEIGHT_CENTRALITY = 0.10


def calculate_reachability_score(factors: ContextFactors) -> float:
    """Calculates normalized reachability score (0 - 100)."""
    if not factors.reachability:
        return 5.0
    if factors.internet_facing:
        # Internet facing and unauthenticated is highest risk
        return 60.0 if factors.auth_required else 100.0
    # Internal component
    return 25.0 if factors.auth_required else 40.0


def compute_contextual_risk_score(
    finding: Finding,
    factors: ContextFactors,
    explanation: Optional[str] = None,
) -> RiskScore:
    """
    Computes deterministic 0 - 100 contextual risk score using weighted multi-factor formula.
    """
    # 1. Base CVSS score (0 - 100)
    cvss_val = finding.cvss or cvss_lookup.get_cvss_score(cwe=finding.cwe)
    s_cvss = cvss_val * 10.0

    # 2. EPSS probability (0 - 100)
    epss_val = finding.epss or epss_lookup.get_epss_score(cwe=finding.cwe)
    s_epss = epss_val * 100.0

    # 3. Reachability (0 - 100)
    s_reach = calculate_reachability_score(factors)

    # 4. Data sensitivity (0 - 100)
    s_sens = DATA_SENSITIVITY_SCORES.get(factors.data_sensitivity.lower(), 40.0)

    # 5. Graph centrality (0 - 100)
    s_cent = factors.graph_centrality * 100.0

    # Weighted sum
    raw_final = (
        (WEIGHT_CVSS * s_cvss)
        + (WEIGHT_EPSS * s_epss)
        + (WEIGHT_REACHABILITY * s_reach)
        + (WEIGHT_SENSITIVITY * s_sens)
        + (WEIGHT_CENTRALITY * s_cent)
    )

    final_score = round(min(100.0, max(0.0, raw_final)), 2)

    # Generate qualitative explanation via LLM
    expl = explanation or threat_explainer.explain(finding, factors)

    return RiskScore(
        finding_id=finding.id,
        base_score=cvss_val,
        context_factors=factors,
        final_score=final_score,
        explanation=expl,
    )


class Prioritizer:
    """Manages baseline and contextual prioritization ranking."""

    def rank_baseline_cvss(self, findings: List[Finding]) -> List[Tuple[Finding, float]]:
        """
        Baseline Ranker: Sorted strictly by CVSS base score descending.
        """
        scored: List[Tuple[Finding, float]] = []
        for f in findings:
            score = f.cvss if f.cvss is not None else cvss_lookup.get_cvss_score(cwe=f.cwe)
            scored.append((f, score))

        scored.sort(key=lambda item: (item[1], item[0].id), reverse=True)
        return scored

    def rank_contextual(
        self,
        findings: List[Finding],
        generate_explanations: bool = True,
    ) -> List[Tuple[Finding, RiskScore]]:
        """
        Contextual Ranker (RQ1): Multi-factor weighted formula combining CVSS, EPSS,
        exposure, reachability, and sensitivity.
        """
        scored: List[Tuple[Finding, RiskScore]] = []

        for f in findings:
            # Enrich context
            factors = context_engine.enrich_finding(f)
            # Ensure CVSS & EPSS are populated on finding
            if f.cvss is None:
                f.cvss = cvss_lookup.get_cvss_score(cwe=f.cwe)
            if f.epss is None:
                f.epss = epss_lookup.get_epss_score(cwe=f.cwe)

            expl = threat_explainer.explain(f, factors) if generate_explanations else ""
            risk_score = compute_contextual_risk_score(finding=f, factors=factors, explanation=expl)
            scored.append((f, risk_score))

        scored.sort(key=lambda item: (item[1].final_score, item[0].id), reverse=True)
        return scored

    def rank_findings(self, findings: List[Finding]) -> List[Finding]:
        """Convenience method returning findings sorted descending by contextual risk score."""
        ranked_tuples = self.rank_contextual(findings, generate_explanations=False)
        result = []
        for f, rs in ranked_tuples:
            f.contextual_score = rs.final_score
            if rs.explanation:
                f.threat_context = rs.explanation
            result.append(f)
        return result


prioritizer = Prioritizer()
contextual_prioritizer = prioritizer
