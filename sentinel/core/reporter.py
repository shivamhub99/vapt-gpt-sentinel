"""
Security Audit & Remediation Reporting Engine for VAPT-GPT Sentinel (Phase 8).
Generates comprehensive Executive & Technical reports in Markdown and standalone HTML.
Includes:
- Scan target metadata & scope authorization.
- Finding inventory & Contextual Risk Prioritization (RQ1).
- Digital Twin attack path modeling & system risk score (RQ2).
- Counterfactual minimum defensive intervention set (RQ3).
- Multi-Agent Red/Blue simulation outcomes & adversary path displacement (Phase 7).
- Deterministic verification audit trail & sandbox git commit diffs.
- Chained SHA-256 cryptographic audit log proof.
"""

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sentinel.agents.simulation import simulation_orchestrator
from sentinel.core.audit_log import audit_logger
from sentinel.core.database import db
from sentinel.core.schemas import Finding, Patch, Verification
from sentinel.core.settings import settings
from sentinel.reasoning.prioritizer import contextual_prioritizer
from sentinel.twin.attack_paths import attack_path_analyzer
from sentinel.twin.builder import twin_builder
from sentinel.twin.counterfactual import counterfactual_engine
from sentinel.twin.risk import system_risk_calculator


class SecurityReporter:
    """Produces multi-format security audit reports with full verification evidence."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or Path(settings.runs_dir) / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _gather_report_data(self, run_id: Optional[str] = None) -> Dict[str, Any]:
        """Gathers all empirical state from database, digital twin, and audit log."""
        # 1. Findings
        if run_id:
            findings = db.get_findings_by_run(run_id)
            effective_run_id = run_id
        else:
            conn = db.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM findings")
            rows = cursor.fetchall()
            conn.close()
            findings = [db.get_finding(r["id"]) for r in rows if db.get_finding(r["id"])]
            effective_run_id = "full_system"

        # Sort findings by contextual risk
        ranked_findings = contextual_prioritizer.rank_findings(findings) if findings else []

        # 2. Patches & Verifications
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM patches")
        patch_rows = cursor.fetchall()
        cursor.execute("SELECT patch_id FROM verifications")
        verif_rows = cursor.fetchall()
        conn.close()

        patches: List[Patch] = [db.get_patch(r["id"]) for r in patch_rows if db.get_patch(r["id"])]
        verifications: List[Verification] = [
            db.get_verification(r["patch_id"])
            for r in verif_rows
            if db.get_verification(r["patch_id"])
        ]

        # 3. Digital Twin & Attack Paths (RQ2)
        twin = twin_builder.build(findings)
        paths = attack_path_analyzer.find_all_attack_paths(twin)
        risk_data = system_risk_calculator.calculate_system_risk(paths)

        # 4. Counterfactual Minimum Defensive Change (RQ3)
        cf_result = (
            counterfactual_engine.evaluate_minimum_defensive_change(twin) if findings else None
        )

        # 5. Multi-Agent Simulation (Phase 7)
        sim_result = (
            simulation_orchestrator.simulate(twin, max_rounds=5, seed=42) if findings else None
        )

        # 6. Audit Log Integrity Check
        audit_valid, audit_count, audit_err = audit_logger.verify_chain()

        return {
            "run_id": effective_run_id,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "findings": ranked_findings,
            "total_findings": len(ranked_findings),
            "patches": patches,
            "verifications": verifications,
            "twin": twin,
            "paths": paths,
            "risk_data": risk_data,
            "counterfactual": cf_result,
            "simulation": sim_result,
            "audit_chain_valid": audit_valid,
            "audit_entries_count": audit_count,
            "audit_error": audit_err,
        }

    def generate_markdown(self, run_id: Optional[str] = None) -> str:
        """Generates a complete, professional GitHub-flavored Markdown security audit report."""
        data = self._gather_report_data(run_id)

        findings: List[Finding] = data["findings"]
        risk_data = data["risk_data"]
        sim = data["simulation"]
        cf = data["counterfactual"]

        # Counts
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        verified_patches = [v for v in data["verifications"] if v.decision.value == "VERIFIED"]

        md = []
        md.append("# VAPT-GPT Sentinel: Defensive Security & Closed-Loop Remediation Report\n")
        md.append(f"**Generated:** {data['generated_at']} | **Run ID:** `{data['run_id']}`\n")
        md.append(
            "> **Defensive Cybersecurity Principle:** LLM proposes candidate prioritizations, "
            "threat narratives, and patches; deterministic test runners and security invariant checkers "
            "decide acceptance. No patch is merged without passing unit tests and rescan checks.\n"
        )
        md.append("---\n")

        # 1. Executive Summary
        md.append("## 1. Executive Summary\n")
        md.append(
            f"- **System Attack Surface Risk Score:** `{risk_data['system_risk_score']} / 100` "
            f"({len(data['paths'])} active attack paths reaching crown jewels)\n"
            f"- **Total Security Findings Discovered:** `{data['total_findings']}` "
            f"(`{sev_counts['CRITICAL']}` Critical, `{sev_counts['HIGH']}` High, `{sev_counts['MEDIUM']}` Medium)\n"
            f"- **Autonomous Remediations Verified:** `{len(verified_patches)}` / `{len(data['patches'])}` patches accepted\n"
            f"- **Residual Risk Post-Intervention:** `{cf.post_risk_score if cf else 0.0} / 100` "
            f"(-{cf.risk_reduction_pct if cf else 0.0:.1f}% risk reduction)\n"
            f"- **Cryptographic Audit Chain Integrity:** "
            f"{'✅ **VALID & UNTAMPERED**' if data['audit_chain_valid'] else '❌ **COMPROMISED**'} "
            f"({data['audit_entries_count']} SHA-256 chained events)\n"
        )
        md.append("---\n")

        # 2. Findings Inventory & Contextual Prioritization (RQ1)
        md.append("## 2. Findings Inventory & Contextual Risk Prioritization (RQ1)\n")
        md.append(
            "| Finding ID | CWE | Vulnerability Title | Severity | CVSS | Contextual Score | Status |\n"
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n"
        )
        for f in findings:
            ctx_score = f"{f.contextual_score:.1f}" if f.contextual_score else "N/A"
            md.append(
                f"| `{f.id}` | `{f.cwe}` | {f.title} | **{f.severity.value}** | `{f.cvss or 0.0}` | **`{ctx_score}`** | `{f.status.value}` |\n"
            )
        md.append("\n")

        # 3. Digital Twin Attack Paths & Crown Jewel Exposure (RQ2)
        md.append("## 3. Digital Twin Attack Surface & Threat Trajectories (RQ2)\n")
        md.append(
            f"The Digital Twin graph modeled **{data['twin'].graph.number_of_nodes()} assets/components** "
            f"and **{data['twin'].graph.number_of_edges()} relationships**.\n\n"
        )

        md.append("### Crown Jewel Exposure Breakdown\n")
        md.append(
            "| Crown Jewel Asset | Criticality | Compromise Probability | Exposure Risk | Reaching Paths |\n"
            "| :--- | :--- | :--- | :--- | :--- |\n"
        )
        for jewel, jdata in risk_data.get("crown_jewel_risks", {}).items():
            md.append(
                f"| **{jewel}** | `{jdata['criticality']:.2f}` | `{jdata['compromise_probability']:.3f}` | "
                f"**`{jdata['risk_score']:.1f}`** | `{jdata['path_count']}` |\n"
            )
        md.append("\n")

        if data["paths"]:
            md.append("### Top Discovered Attack Paths\n")
            md.append(
                "| Path ID | Target Asset | Probability | Attacker Cost | Risk Contribution | Trajectory Narrative |\n"
                "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
            )
            for p in data["paths"][:5]:
                md.append(
                    f"| `{p.path_id}` | `{p.target_crown_jewel}` | `{p.probability:.3f}` | `{p.attacker_cost:.1f}` | "
                    f"`{p.risk_contribution:.1f}` | {p.description} |\n"
                )
            md.append("\n")

        # 4. Counterfactual Minimum Defensive Solution (RQ3)
        if cf:
            md.append("## 4. Counterfactual Minimum Defensive Solution (RQ3)\n")
            md.append(
                f"- **Optimization Goal:** Minimize operational cost while cutting top attack paths.\n"
                f"- **Baseline System Risk:** `{cf.pre_risk_score:.1f}` ➔ **Residual System Risk:** `{cf.post_risk_score:.1f}`\n"
                f"- **Risk Reduction:** `-{cf.risk_reduction_pct:.1f}%` at total operational cost `{cf.total_cost:.1f}`\n"
                f"- **Disrupted Attack Trajectories:** `{cf.disrupted_paths_count}` / `{cf.disrupted_paths_count + cf.residual_paths_count}`\n\n"
                f"**Optimal Intervention Set:**\n"
            )
            for act in cf.recommended_interventions:
                md.append(
                    f"- **[{act.action_type}]** `{act.target_label}` (Cost: `{act.cost:.1f}`): {act.description}\n"
                )
            md.append("\n")

        # 5. Multi-Agent Red/Blue Game Simulation (Phase 7)
        if sim:
            md.append("## 5. Multi-Agent In-Memory Game Simulation (Phase 7)\n")
            md.append(
                f"- **Simulation Outcome:** `{sim.winner}` (Deterministic Seed: `{sim.seed}`, Rounds: `{len(sim.rounds)}`)\n"
                f"- **Risk Trajectory:** `{sim.initial_risk_score:.1f}` ➔ `{sim.final_risk_score:.1f}` (-{sim.total_risk_reduction_pct:.1f}%)\n"
                f"- **Adversary Containment Status:** {sim.stop_reason}\n\n"
                "| Round | Red Move (Attacker) | Blue Move (Defender) | Pre ➔ Post Risk | Paths Left | Displacement |\n"
                "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
            )
            for r in sim.rounds:
                red_str = (
                    f"Target `{r.red_move.targeted_crown_jewel}` (Util: {r.red_move.attack_utility:.2f})"
                    if r.red_move
                    else "None"
                )
                blue_str = (
                    f"`{r.blue_move.action_type}` on `{r.blue_move.target}`"
                    if r.blue_move
                    else "None"
                )
                disp_str = f"⚠️ Displaced to `{r.displaced_to}`" if r.path_displaced else "None"
                md.append(
                    f"| {r.round_number} | {red_str} | {blue_str} | `{r.pre_round_risk:.1f} ➔ {r.post_round_risk:.1f}` | `{r.paths_remaining}` | {disp_str} |\n"
                )
            md.append("\n")

        # 6. Remediation & Verification Audit Trail
        md.append("## 6. Deterministic Remediation & Verification Audit Trail\n")
        if data["patches"]:
            md.append(
                "| Patch ID | Finding ID | Sandbox Branch | Attempt | Unit Tests | Regression Invariants | Rescan (Flaw Removed) | Decision |\n"
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n"
            )
            for p in data["patches"]:
                # Lookup verification
                v = next((x for x in data["verifications"] if x.patch_id == p.id), None)
                unit_str = "✅ PASS" if (v and v.unit_passed) else "❌ FAIL"
                reg_str = "✅ PASS" if (v and v.regression_passed) else "❌ FAIL"
                rescan_str = "✅ ELIMINATED" if (v and v.original_finding_gone) else "❌ ACTIVE"
                dec_str = f"**`{v.decision.value}`**" if v else "`PENDING`"
                md.append(
                    f"| `{p.id}` | `{p.finding_id}` | `{p.branch}` | `{p.attempt}` | {unit_str} | {reg_str} | {rescan_str} | {dec_str} |\n"
                )
            md.append("\n")
        else:
            md.append("No remediation patches generated in this run.\n\n")

        # 7. Chained SHA-256 Audit Integrity
        md.append("## 7. Cryptographic Chained Audit Trail Verification\n")
        md.append(f"- **Log File:** `{audit_logger.log_path}`\n")
        md.append(f"- **Recorded Security Events:** `{data['audit_entries_count']}` entries\n")
        chain_status = (
            "VALID (SHA-256 Chained Integrity Confirmed)"
            if data["audit_chain_valid"]
            else f"INVALID: {data['audit_error']}"
        )
        md.append(f"- **Cryptographic Chain State:** {chain_status}\n")

        return "".join(md)

    def generate_html(self, run_id: Optional[str] = None) -> str:
        """Generates a standalone, beautiful HTML report with modern dark theme styling."""
        data = self._gather_report_data(run_id)
        findings: List[Finding] = data["findings"]
        risk_data = data["risk_data"]
        cf = data["counterfactual"]

        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        verified_patches = [v for v in data["verifications"] if v.decision.value == "VERIFIED"]

        findings_rows = ""
        for f in findings:
            ctx_score = f"{f.contextual_score:.1f}" if f.contextual_score else "N/A"
            sev_badge = (
                f'<span class="badge badge-{f.severity.value.lower()}">{f.severity.value}</span>'
            )
            findings_rows += f"""
            <tr>
                <td><code>{html.escape(f.id)}</code></td>
                <td><code>{html.escape(f.cwe)}</code></td>
                <td><strong>{html.escape(f.title)}</strong><br><small class="text-muted">{html.escape(f.file or f.endpoint or "")}</small></td>
                <td>{sev_badge}</td>
                <td><code>{f.cvss or 0.0}</code></td>
                <td><strong><code>{ctx_score}</code></strong></td>
                <td><span class="badge badge-info">{html.escape(f.status.value)}</span></td>
            </tr>
            """

        jewel_rows = ""
        for jewel, jdata in risk_data.get("crown_jewel_risks", {}).items():
            jewel_rows += f"""
            <tr>
                <td><strong>{html.escape(jewel)}</strong></td>
                <td><code>{jdata["criticality"]:.2f}</code></td>
                <td><code>{jdata["compromise_probability"]:.3f}</code></td>
                <td><strong class="text-danger"><code>{jdata["risk_score"]:.1f}</code></strong></td>
                <td>{jdata["path_count"]}</td>
            </tr>
            """

        patch_rows = ""
        for p in data["patches"]:
            v = next((x for x in data["verifications"] if x.patch_id == p.id), None)
            unit_badge = (
                '<span class="badge badge-success">PASS</span>'
                if (v and v.unit_passed)
                else '<span class="badge badge-danger">FAIL</span>'
            )
            reg_badge = (
                '<span class="badge badge-success">PASS</span>'
                if (v and v.regression_passed)
                else '<span class="badge badge-danger">FAIL</span>'
            )
            rescan_badge = (
                '<span class="badge badge-success">ELIMINATED</span>'
                if (v and v.original_finding_gone)
                else '<span class="badge badge-danger">ACTIVE</span>'
            )
            dec_badge = (
                f'<span class="badge badge-success">{v.decision.value}</span>'
                if (v and v.decision.value == "VERIFIED")
                else f'<span class="badge badge-danger">{v.decision.value if v else "PENDING"}</span>'
            )

            patch_rows += f"""
            <tr>
                <td><code>{html.escape(p.id)}</code></td>
                <td><code>{html.escape(p.finding_id)}</code></td>
                <td><code>{html.escape(p.branch)}</code></td>
                <td>{p.attempt}</td>
                <td>{unit_badge}</td>
                <td>{reg_badge}</td>
                <td>{rescan_badge}</td>
                <td>{dec_badge}</td>
            </tr>
            """

        audit_badge = (
            '<span class="badge badge-success">VALID & UNTAMPERED</span>'
            if data["audit_chain_valid"]
            else '<span class="badge badge-danger">COMPROMISED</span>'
        )

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VAPT-GPT Sentinel Security Audit Report</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700;800&display=swap');

        :root {{
            --bg-primary: #0a0a0a;
            --bg-secondary: #111111;
            --bg-card: #0e0e0e;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-green: #00ff41;
            --accent-green-hover: #33ff66;
            --accent-red: #ff3344;
            --accent-yellow: #ffaa00;
            --accent-cyan: #00e5ff;
            --border-color: rgba(0, 255, 65, 0.22);
            --border-hover: rgba(0, 255, 65, 0.5);
            --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            --font-mono: 'JetBrains Mono', 'Fira Code', Menlo, Monaco, Consolas, monospace;
        }}
        html {{
            scroll-behavior: smooth;
        }}
        ::-webkit-scrollbar {{
            width: 8px;
            height: 8px;
        }}
        ::-webkit-scrollbar-track {{
            background: #0a0a0a;
        }}
        ::-webkit-scrollbar-thumb {{
            background: rgba(0, 255, 65, 0.3);
            border-radius: 4px;
            border: 2px solid #0a0a0a;
        }}
        ::-webkit-scrollbar-thumb:hover {{
            background: #00ff41;
            box-shadow: 0 0 10px #00ff41;
        }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: var(--font-sans);
            margin: 0;
            padding: 36px 24px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1300px;
            margin: 0 auto;
        }}
        .terminal-window {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 28px;
            overflow: hidden;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.7), 0 0 20px rgba(0, 255, 65, 0.08);
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }}
        .terminal-window:hover {{
            border-color: var(--border-hover);
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.8), 0 0 25px rgba(0, 255, 65, 0.15);
        }}
        .terminal-topbar {{
            background: #050505;
            padding: 8px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            font-family: var(--font-mono);
            font-size: 12px;
        }}
        .terminal-cmd {{
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .prompt-user {{ color: var(--accent-green); font-weight: 700; }}
        .prompt-path {{ color: #38bdf8; }}
        .terminal-controls {{ display: flex; gap: 8px; }}
        .t-btn {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 18px;
            height: 18px;
            border: 1px solid rgba(0, 255, 65, 0.35);
            border-radius: 3px;
            color: var(--accent-green);
            font-family: var(--font-mono);
            font-size: 11px;
            background: rgba(0, 255, 65, 0.05);
        }}
        .header {{
            padding: 26px 28px;
            background: linear-gradient(180deg, #111111 0%, #0a0a0a 100%);
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 26px;
            font-family: var(--font-mono);
            font-weight: 800;
            color: var(--accent-green);
            text-shadow: 0 0 12px rgba(0, 255, 65, 0.3);
            letter-spacing: -0.01em;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }}
        .kpi-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
            transition: all 0.25s ease;
        }}
        .kpi-card:hover {{
            border-color: var(--border-hover);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.6), 0 0 15px rgba(0, 255, 65, 0.15);
            transform: translateY(-2px);
        }}
        .kpi-label {{
            font-family: var(--font-mono);
            color: var(--text-secondary);
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 6px;
        }}
        .kpi-value {{
            font-family: var(--font-mono);
            font-size: 32px;
            font-weight: 800;
            margin: 8px 0;
            letter-spacing: -0.02em;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
        }}
        .card h2 {{
            margin-top: 0;
            font-family: var(--font-mono);
            color: var(--accent-green);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 12px;
            font-size: 18px;
            letter-spacing: -0.01em;
        }}
        .table-responsive {{
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
            font-size: 13.5px;
        }}
        th, td {{
            text-align: left;
            padding: 12px 14px;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: #050505;
            color: var(--accent-green);
            font-family: var(--font-mono);
            font-weight: 700;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }}
        tbody tr:hover {{
            background-color: rgba(0, 255, 65, 0.03);
        }}
        code {{
            background: #050505;
            padding: 3px 6px;
            border-radius: 4px;
            border: 1px solid rgba(0, 255, 65, 0.2);
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--accent-green);
        }}
        .badge {{
            display: inline-block;
            padding: 3px 9px;
            border-radius: 4px;
            font-family: var(--font-mono);
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }}
        .badge-critical {{ background: rgba(255, 51, 68, 0.12); color: #ff3344; border: 1px solid rgba(255, 51, 68, 0.4); }}
        .badge-high {{ background: rgba(255, 170, 0, 0.12); color: #ffaa00; border: 1px solid rgba(255, 170, 0, 0.4); }}
        .badge-medium {{ background: rgba(255, 215, 0, 0.12); color: #ffd700; border: 1px solid rgba(255, 215, 0, 0.4); }}
        .badge-low {{ background: rgba(0, 229, 255, 0.12); color: #00e5ff; border: 1px solid rgba(0, 229, 255, 0.4); }}
        .badge-success {{ background: rgba(0, 255, 65, 0.12); color: var(--accent-green); border: 1px solid var(--accent-green); }}
        .badge-danger {{ background: rgba(255, 51, 68, 0.12); color: #ff3344; border: 1px solid rgba(255, 51, 68, 0.4); }}
        .badge-info {{ background: rgba(0, 229, 255, 0.12); color: #00e5ff; border: 1px solid rgba(0, 229, 255, 0.4); }}
        .text-muted {{ color: var(--text-secondary); font-size: 12px; }}
        .text-danger {{ color: var(--accent-red) !important; }}
        .text-success {{ color: var(--accent-green) !important; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="terminal-window">
            <div class="terminal-topbar">
                <div class="terminal-cmd">
                    <span class="prompt-user">sentinel@audit-workstation</span>:<span class="prompt-path">~/reports</span>$
                    <span>./sentinel-reporter --format=html --verified</span>
                </div>
                <div class="terminal-controls">
                    <span class="t-btn">_</span>
                    <span class="t-btn">□</span>
                    <span class="t-btn">×</span>
                </div>
            </div>
            <div class="header">
                <h1>🛡️ VAPT-GPT Sentinel: Defensive Security & Remediation Report</h1>
                <p style="margin: 0; color: var(--text-secondary); font-family: var(--font-mono); font-size: 13px;">
                    <strong>Run ID:</strong> <code>{html.escape(data["run_id"])}</code> |
                    <strong>Generated:</strong> {html.escape(data["generated_at"])} |
                    <strong>Audit Integrity:</strong> {audit_badge}
                </p>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div style="color: var(--text-secondary); font-size: 13px;">System Risk Score</div>
                <div class="kpi-value text-danger">{risk_data["system_risk_score"]} / 100</div>
                <small class="text-muted">{len(data["paths"])} active attack paths</small>
            </div>
            <div class="kpi-card">
                <div style="color: var(--text-secondary); font-size: 13px;">Security Findings</div>
                <div class="kpi-value">{data["total_findings"]}</div>
                <small class="text-muted">{sev_counts["CRITICAL"]} Crit | {sev_counts["HIGH"]} High</small>
            </div>
            <div class="kpi-card">
                <div style="color: var(--text-secondary); font-size: 13px;">Verified Autonomous Patches</div>
                <div class="kpi-value text-success">{len(verified_patches)} / {len(data["patches"])}</div>
                <small class="text-muted">100% deterministic verification</small>
            </div>
            <div class="kpi-card">
                <div style="color: var(--text-secondary); font-size: 13px;">Post-Intervention Residual Risk</div>
                <div class="kpi-value text-success">{cf.post_risk_score if cf else 0.0} / 100</div>
                <small class="text-muted">-{cf.risk_reduction_pct if cf else 0.0:.1f}% risk reduction</small>
            </div>
        </div>

        <div class="card">
            <h2>1. Security Findings & Contextual Prioritization (RQ1)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Finding ID</th>
                        <th>CWE</th>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>CVSS</th>
                        <th>Contextual</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows or '<tr><td colspan="7">No findings reported.</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>2. Digital Twin Crown Jewel Asset Exposure (RQ2)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Crown Jewel Asset</th>
                        <th>Criticality</th>
                        <th>Compromise Probability</th>
                        <th>Exposure Risk</th>
                        <th>Active Attack Paths</th>
                    </tr>
                </thead>
                <tbody>
                    {jewel_rows or '<tr><td colspan="5">No crown jewels exposed.</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>3. Autonomous Remediation & Deterministic Verification Audit Trail</h2>
            <table>
                <thead>
                    <tr>
                        <th>Patch ID</th>
                        <th>Finding ID</th>
                        <th>Sandbox Branch</th>
                        <th>Attempt</th>
                        <th>Unit Tests</th>
                        <th>Regression</th>
                        <th>Rescan</th>
                        <th>Decision</th>
                    </tr>
                </thead>
                <tbody>
                    {patch_rows or '<tr><td colspan="8">No patches created in this run.</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>4. Cryptographic Chained Audit Trail Verification</h2>
            <p>
                <strong>Audit Log Path:</strong> <code>{html.escape(str(audit_logger.log_path))}</code><br>
                <strong>Total Chained Security Events:</strong> <code>{data["audit_entries_count"]}</code><br>
                <strong>Integrity Status:</strong> {audit_badge}
            </p>
        </div>
    </div>
</body>
</html>
"""
        return html_template

    def export_report(
        self, run_id: Optional[str] = None, output_dir: Optional[Path] = None
    ) -> Dict[str, Path]:
        """Saves both Markdown and HTML audit reports to the designated directory."""
        target_dir = output_dir or self.output_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        effective_id = run_id or "full_system"
        md_path = target_dir / f"sentinel_report_{effective_id}.md"
        html_path = target_dir / f"sentinel_report_{effective_id}.html"

        md_content = self.generate_markdown(run_id)
        html_content = self.generate_html(run_id)

        md_path.write_text(md_content, encoding="utf-8")
        html_path.write_text(html_content, encoding="utf-8")

        return {"markdown": md_path, "html": html_path}


security_reporter = SecurityReporter()
