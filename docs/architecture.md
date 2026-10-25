# VAPT-GPT Sentinel Architecture Specification

## Overview
VAPT-GPT Sentinel is a closed-loop defensive security framework designed for academic vulnerability assessment, prioritization, remediation, and verification.

### Core Pipeline
1. **Scope Verification**: `ScopeGuard` verifies CIDR allowlists and environment ownership authorization.
2. **Scan Ingestion**: Wraps open-source baseline tools (ZAP, Semgrep, Bandit, Gitleaks, Trivy, pip-audit, Nmap, Headers).
3. **Normalization**: Converts raw tool outputs into canonical `Finding` models mapped to CWE & OWASP Top 10.
4. **Contextual Risk Prioritization (RQ1)**: Computes risk scores combining CVSS, EPSS, network reachability, and asset sensitivity.
5. **Remediation**: Generates parameterized/encoded patches via AST templates or LLM prompts.
6. **Verification State Machine (Core Contribution)**: Rebuilds sandbox, runs functional & security regression suites, rescans, and triggers automatic rollback on regressions.
7. **Digital Twin & Counterfactual Engine (RQ2, RQ3)**: NetworkX attack graph calculating cumulative path probability and finding the minimum defensive intervention set.
