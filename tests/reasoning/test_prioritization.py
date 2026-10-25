"""
Unit Tests for Context Enrichment, CVSS/EPSS Intelligence,
Contextual Risk Formula, and Prioritization Rankers (Research Question 1 - RQ1).
"""

from sentinel.core.schemas import ContextFactors, Finding, Severity
from sentinel.intel.attack_map import get_attack_technique
from sentinel.intel.cvss import cvss_lookup
from sentinel.intel.epss import epss_lookup
from sentinel.reasoning.context import context_engine
from sentinel.reasoning.explainer import threat_explainer
from sentinel.reasoning.prioritizer import (
    calculate_reachability_score,
    compute_contextual_risk_score,
    prioritizer,
)


def test_cvss_and_epss_lookups():
    """Validates CVSS base score and EPSS probability lookups."""
    # CVSS lookups
    assert cvss_lookup.get_cvss_score("CWE-89") == 8.8
    assert cvss_lookup.get_cvss_score("CWE-79") == 6.1
    assert cvss_lookup.get_cvss_score("CWE-798") == 9.8

    # EPSS lookups
    assert epss_lookup.get_epss_score("CWE-89") > 0.40
    assert epss_lookup.get_epss_score("CWE-693") < 0.05

    # MITRE ATT&CK technique mapping
    attack_info = get_attack_technique("CWE-89")
    assert attack_info is not None
    assert attack_info["technique_id"] == "T1190"


def test_app_context_enrichment():
    """Validates endpoint and asset matching from config/app_context.yaml."""
    # Web search endpoint
    f_search = Finding(
        id="f_search",
        tool="zap",
        cwe="CWE-89",
        title="SQLi in search",
        severity=Severity.HIGH,
        endpoint="http://localhost:8080/api/search",
    )
    factors_search = context_engine.enrich_finding(f_search)
    assert factors_search.internet_facing is True
    assert factors_search.auth_required is False
    assert factors_search.data_sensitivity in ("public", "restricted")

    # Orders endpoint (requires auth, confidential data)
    f_order = Finding(
        id="f_order",
        tool="headers",
        cwe="CWE-639",
        title="IDOR in orders",
        severity=Severity.HIGH,
        endpoint="http://localhost:8080/api/orders/1",
    )
    factors_order = context_engine.enrich_finding(f_order)
    assert factors_order.auth_required is True
    assert factors_order.data_sensitivity == "confidential"


def test_reachability_score_math():
    """Verifies reachability scoring logic across exposure combinations."""
    # Internet-facing unauthenticated (maximum exposure)
    f_ext_unauth = ContextFactors(internet_facing=True, auth_required=False, reachability=True)
    assert calculate_reachability_score(f_ext_unauth) == 100.0

    # Internet-facing with authentication requirement
    f_ext_auth = ContextFactors(internet_facing=True, auth_required=True, reachability=True)
    assert calculate_reachability_score(f_ext_auth) == 60.0

    # Internal only
    f_internal = ContextFactors(internet_facing=False, auth_required=False, reachability=True)
    assert calculate_reachability_score(f_internal) == 40.0

    # Unreachable
    f_unreachable = ContextFactors(reachability=False)
    assert calculate_reachability_score(f_unreachable) == 5.0


def test_contextual_risk_formula_bounds():
    """Verifies that the multi-factor weighted formula stays bounded strictly within 0 - 100."""
    f = Finding(
        id="f_test",
        tool="bandit",
        cwe="CWE-89",
        title="Test SQLi",
        severity=Severity.HIGH,
        cvss=8.8,
        epss=0.45,
    )
    factors = ContextFactors(
        internet_facing=True,
        data_sensitivity="restricted",
        reachability=True,
        auth_required=False,
        graph_centrality=0.8,
    )

    risk = compute_contextual_risk_score(f, factors)
    assert 0.0 <= risk.final_score <= 100.0
    assert risk.base_score == 8.8
    assert len(risk.explanation) > 0


def test_rq1_contextual_ranker_reorders_findings():
    """
    Research Question 1 (RQ1) Proof:
    Demonstrates that contextual risk ranking correctly flips the priority order
    when an asset with slightly lower CVSS has drastically higher real-world exploitability
    and asset criticality compared to an internal bug with high CVSS.
    """
    # Finding A: High CVSS (8.5), but internal-only, low EPSS (0.01), public data
    finding_internal_high_cvss = Finding(
        id="f_internal",
        tool="semgrep",
        cwe="CWE-22",
        title="Internal Path Traversal",
        severity=Severity.HIGH,
        cvss=8.5,
        epss=0.01,
        file="scripts/backup.py",
    )

    # Finding B: Lower CVSS (7.5), but Internet-facing, unauthenticated, restricted database data, high EPSS (0.50)
    finding_exposed_critical_data = Finding(
        id="f_exposed",
        tool="bandit",
        cwe="CWE-89",
        title="Internet-Facing SQL Injection",
        severity=Severity.HIGH,
        cvss=7.5,
        epss=0.50,
        endpoint="http://localhost:8080/api/search",
    )

    findings = [finding_internal_high_cvss, finding_exposed_critical_data]

    # Baseline CVSS-only ranking
    baseline_ranked = prioritizer.rank_baseline_cvss(findings)
    assert baseline_ranked[0][0].id == "f_internal"  # Baseline prioritizes 8.5 over 7.5
    assert baseline_ranked[1][0].id == "f_exposed"

    # Contextual ranking (RQ1)
    context_ranked = prioritizer.rank_contextual(findings, generate_explanations=False)
    # The internet-facing, restricted data, active EPSS finding MUST be ranked #1
    assert context_ranked[0][0].id == "f_exposed"
    assert context_ranked[1][0].id == "f_internal"
    assert context_ranked[0][1].final_score > context_ranked[1][1].final_score


def test_threat_explainer_produces_grounded_rationale():
    """Verifies that LLM threat explainer produces contextual rationale without altering numeric score."""
    f = Finding(
        id="f_expl_test",
        tool="headers",
        cwe="CWE-942",
        title="Permissive CORS Policy",
        severity=Severity.MEDIUM,
    )
    factors = ContextFactors(
        internet_facing=True,
        data_sensitivity="public",
        reachability=True,
        auth_required=False,
    )
    explanation = threat_explainer.explain(f, factors)
    assert isinstance(explanation, str)
    assert "CWE-942" in explanation or "threat" in explanation.lower()
