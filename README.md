# VAPT-GPT Sentinel

> **A Defensive Closed-Loop Vulnerability Remediation and Attack-Path Digital Twin Framework**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Safety: Scope Guarded](https://img.shields.io/badge/safety-scope__guarded-red.svg)](config/scope.yaml)

---

## Key Principles
1. **Defensive Closed-Loop**: Scans -> Normalizes -> Prioritizes -> Fixes -> Verifies -> Accepts or Rolls Back -> Models Attack Paths.
2. **LLM Proposes, Deterministic Checks Decide**: The LLM suggests patches and explanations, but automated test harnesses and rescans strictly decide whether a patch is verified.
3. **Hard Scope & Authorization Guards**: Refuses to run without `SENTINEL_I_OWN_THIS_TARGET=true` and explicit CIDR/host allowlisting.
4. **Digital Twin Counterfactuals**: Calculates attack path reachability in an in-memory NetworkX graph to determine the minimum defensive change required to mitigate maximum risk.

---

## Lab Quickstart

### 1. Environment Configuration
```bash
cp .env.example .env
# Edit .env to set SENTINEL_I_OWN_THIS_TARGET=true
```

### 2. Launch the Lab Targets
```bash
docker compose -f lab/docker-compose.yml up -d
```
The lab starts three isolated targets:
- `sentinel-lab-app` on port 8080 (Custom Flask app with 6 planted findings)
- `DVWA` on port 8081
- `OWASP Juice Shop` on port 8082

### 3. Run Functional Tests
```bash
pytest lab/sentinel-lab-app/tests/
```
