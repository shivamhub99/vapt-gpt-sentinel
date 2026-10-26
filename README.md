# VAPT-GPT Sentinel: User Manual & Execution Guide

> **A Defensive Closed-Loop Vulnerability Remediation, Attack-Path Digital Twin & Academic Evaluation Framework**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Safety: Scope Guarded](https://img.shields.io/badge/safety-scope__guarded-red.svg)](config/scope.yaml)
[![Tests: 80 Passed](https://img.shields.io/badge/tests-80%20passed-brightgreen.svg)](tests/)

---

## 1. Quick Environment Setup

### Step 1: Open PowerShell in Project Root
```powershell
cd "D:\NFSU\SEM - 9\MAJOR"
```

### Step 2: Ensure Target Ownership Authorization in `.env`
Ensure `.env` exists and contains the safety authorization:
```ini
SENTINEL_I_OWN_THIS_TARGET=true
SENTINEL_SAFE_MODE=true
```

### Step 3: Check Lab Targets (Docker)
Ensure Docker Desktop is running and verify the three isolated lab containers:
```powershell
docker compose -f lab/docker-compose.yml up -d
```
Lab endpoints:
- **Sentinel Lab App (Port 8080)**: `http://localhost:8080` (Planted with SQLi, XSS, Secret, IDOR, Dependency, Headers)
- **DVWA (Port 8081)**: `http://localhost:8081`
- **OWASP Juice Shop (Port 8082)**: `http://localhost:8082`

---

## 2. Running Automated Tests

Run the full verification suite across all 10 project phases:
```powershell
.\.venv\Scripts\pytest -v tests/
```
Or run the fast unit tests (~15 seconds):
```powershell
.\.venv\Scripts\pytest -v tests/evaluation/ tests/dashboard/ tests/core/ tests/agents/ tests/twin/ tests/reasoning/ tests/normalize/ tests/remediation/
```

---

## 3. Step-by-Step CLI Walkthrough

### 1. Check Framework Status & Safety Boundaries
```powershell
.\.venv\Scripts\sentinel status
```
*Outputs target ownership status, allowed hostnames/CIDRs, allowed ports, and cryptographic audit log location.*

### 2. Scan a Target Application
Scan the local web application or repository:
```powershell
.\.venv\Scripts\sentinel scan --target http://localhost:8080
```

### 3. Inspect Discovered Vulnerabilities
View the normalized findings stored in the SQLite database:
```powershell
.\.venv\Scripts\sentinel findings
```

### 4. Run Contextual Risk Prioritization (RQ1)
Compare static CVSS Base Scores against multi-factor Contextual Risk scores:
```powershell
.\.venv\Scripts\sentinel prioritize
```

### 5. Analyze Digital Twin Attack Surface (RQ2)
Discover all multi-step paths reaching crown jewels (`database`, `orders_ledger`) and calculate system risk:
```powershell
.\.venv\Scripts\sentinel twin paths
.\.venv\Scripts\sentinel twin risk
```

### 6. Solve Minimum Defensive Cut (RQ3)
Find the minimal-cost intervention set that drops attack surface risk below a threshold:
```powershell
.\.venv\Scripts\sentinel twin counterfactual --threshold 40.0
```

### 7. Run Multi-Agent Red/Blue/Judge Simulation (Phase 7)
Execute in-memory turn-based game rounds with zero network traffic:
```powershell
.\.venv\Scripts\sentinel twin simulate --max-rounds 5 --seed 42
```

### 8. Propose and Verify an Autonomous Patch (Phases 4 & 5)
Propose a patch in an isolated sandbox branch:
```powershell
.\.venv\Scripts\sentinel fix --finding e2e_sqli_find
```
Execute the 4-stage deterministic verification state machine:
```powershell
.\.venv\Scripts\sentinel verify --patch-id patch_e2e_sqli_find_att1
```

### 9. Run the Complete Closed-Loop Pipeline in ONE Command
Runs Scope Check -> Scanners -> Normalize -> Prioritize (RQ1) -> Digital Twin (RQ2) -> Sandbox Fix -> 4-Stage Verification -> Game Simulation -> Generates Audit Reports:
```powershell
.\.venv\Scripts\sentinel run --target http://localhost:8080
```

### 10. Generate Security Audit Reports (Phase 8)
Generates both Markdown and HTML reports under `runs/reports/`:
```powershell
.\.venv\Scripts\sentinel report
```

### 11. Run Academic Benchmark & Generate Thesis Figures (Phase 9)
Executes the evaluation harness comparing against CVSS-only and Scanner-only baselines, generating CSVs and publication-quality PNG charts in `evaluation/results/`:
```powershell
.\.venv\Scripts\sentinel evaluate --budget 2
```

---

## 4. Interactive Streamlit Web Dashboard

To launch the interactive Security Operations & Digital Twin Dashboard:
```powershell
.\.venv\Scripts\sentinel dashboard
```
*Or directly via Streamlit:*
```powershell
.\.venv\Scripts\streamlit run dashboard/app.py
```
Open **`http://localhost:8501`** in your browser.

### Dashboard Navigation:
- **📊 Executive Overview**: High-level KPIs, Crown Jewel exposure cards, and top threat paths.
- **🔍 Findings & Context (RQ1)**: Filterable finding tables comparing Contextual Risk vs CVSS base score, with detailed threat rationale drawers.
- **🌐 Digital Twin (RQ2)**: Live Mermaid.js attack graph topology flowchart and step-by-step exploit trajectories.
- **🛠️ Verification & Sandbox**: Patch diff viewer with syntax highlighting and 4-stage deterministic checklist status.
- **♟️ Red/Blue Simulation (Phase 7)**: Interactive counterfactual sliders and turn-by-turn game simulation replay.
- **📜 Reports & Audit Trail**: Cryptographic SHA-256 chained audit ledger viewer and live report exporter.

---

## 5. How to Test Any Arbitrary Software / Target

To scan and patch an arbitrary new project or application:
1. **Add Target to Scope Allowlist**: Edit `config/scope.yaml` to include the target's IP, hostname, or port under `allowlist`.
2. **Configure Application Context**: Edit `config/app_context.yaml` to define your application's crown jewel datastores, sensitive data types, and endpoint exposure.
3. **Run Closed-Loop Sentinel**:
   ```powershell
   .\.venv\Scripts\sentinel run --target http://<your-app-host>:<port> --repo <path-to-source-repo>
   ```
4. **View Verified Results**:
   Sentinel will scan the target, build the digital twin, propose fixes in an isolated sandbox copy, run functional tests, verify security invariants, and produce verifiable audit reports!
