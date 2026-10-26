"""
Streamlit Web Dashboard for VAPT-GPT Sentinel (Phase 8).
Interactive digital twin security visualization, finding prioritization (RQ1),
deterministic verification inspector, counterfactual simulator (RQ3),
and Red/Blue turn-based game replay (Phase 7).
"""

import streamlit as st

from sentinel.agents.simulation import simulation_orchestrator
from sentinel.core.audit_log import audit_logger
from sentinel.core.database import db
from sentinel.core.reporter import security_reporter
from sentinel.core.schemas import Severity
from sentinel.reasoning.prioritizer import contextual_prioritizer
from sentinel.twin.attack_paths import attack_path_analyzer
from sentinel.twin.builder import twin_builder
from sentinel.twin.counterfactual import counterfactual_engine
from sentinel.twin.risk import system_risk_calculator

# --- Page Configuration & Styling ---
st.set_page_config(
    page_title="VAPT-GPT Sentinel | Security Operations & Digital Twin",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
        /* Modern Glassmorphic Dark Theme */
        .stApp {
            background-color: #0b0f19;
            color: #f1f5f9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        .main-header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
        }
        .metric-card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 18px;
            text-align: center;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
        }
        .badge-critical { background: #991b1b; color: #fee2e2; }
        .badge-high { background: #c2410c; color: #ffedd5; }
        .badge-medium { background: #b45309; color: #fef3c7; }
        .badge-low { background: #1e3a8a; color: #dbeafe; }
        .badge-verified { background: #065f46; color: #a7f3d0; }
        .badge-rejected { background: #881337; color: #fecdd3; }
        .stTabs [data-baseweb="tab-list"] {
            gap: 10px;
        }
        .stTabs [data-baseweb="tab"] {
            background-color: #1e293b;
            border-radius: 8px 8px 0px 0px;
            padding: 10px 20px;
            color: #94a3b8;
            border: 1px solid #334155;
            border-bottom: none;
        }
        .stTabs [aria-selected="true"] {
            background-color: #0284c7 !important;
            color: #ffffff !important;
            font-weight: bold;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


def load_findings():
    """Fetches findings from SQLite database."""
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM findings")
    rows = cursor.fetchall()
    conn.close()
    return [db.get_finding(r["id"]) for r in rows if db.get_finding(r["id"])]


def load_patches_and_verifications():
    """Fetches remediation patches and verification outcomes from SQLite."""
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM patches")
    patch_rows = cursor.fetchall()
    cursor.execute("SELECT patch_id FROM verifications")
    verif_rows = cursor.fetchall()
    conn.close()

    patches = [db.get_patch(r["id"]) for r in patch_rows if db.get_patch(r["id"])]
    verifications = [
        db.get_verification(r["patch_id"]) for r in verif_rows if db.get_verification(r["patch_id"])
    ]
    return patches, verifications


# --- Data Ingestion ---
all_findings = load_findings()
ranked_findings = contextual_prioritizer.rank_findings(all_findings) if all_findings else []
twin = twin_builder.build(ranked_findings)
attack_paths = attack_path_analyzer.find_all_attack_paths(twin)
risk_data = system_risk_calculator.calculate_system_risk(attack_paths)
patches, verifications = load_patches_and_verifications()
audit_valid, audit_count, audit_err = audit_logger.verify_chain()

# --- Sidebar Controls ---
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
st.sidebar.title("VAPT-GPT Sentinel")
st.sidebar.markdown("**Defensive Cybersecurity Framework**")
st.sidebar.markdown("**Target System:** `localhost:8080` (Lab)")
st.sidebar.markdown(f"**Database:** `lab.db` ({len(all_findings)} findings)")
st.sidebar.markdown("---")

# Quick Stats in Sidebar
st.sidebar.metric("System Risk Score", f"{risk_data['system_risk_score']} / 100")
st.sidebar.metric("Attack Paths", len(attack_paths))
st.sidebar.metric(
    "Verified Patches", sum(1 for v in verifications if v.decision.value == "VERIFIED")
)
st.sidebar.metric("Chained Audit Events", audit_count)

if st.sidebar.button("🔄 Refresh Data", use_container_width=True):
    st.rerun()

# --- Header Banner ---
st.markdown(
    """
    <div class="main-header">
        <h1 style="margin: 0; color: #38bdf8; font-size: 28px;">🛡️ VAPT-GPT Sentinel Operations Console</h1>
        <p style="margin: 6px 0 0 0; color: #94a3b8; font-size: 15px;">
            Closed-Loop Defensive Vulnerability Remediation, Attack-Path Digital Twin & Counterfactual Reasoning Engine
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# --- Top Navigation Tabs ---
tab_overview, tab_findings, tab_twin, tab_remediation, tab_simulation, tab_reports = st.tabs(
    [
        "📊 Executive Overview",
        "🔍 Findings & Context (RQ1)",
        "🌐 Digital Twin (RQ2)",
        "🛠️ Verification & Sandbox (RQ3)",
        "♟️ Red/Blue Simulation (Phase 7)",
        "📜 Reports & Audit Trail",
    ]
)

# ==========================================
# TAB 1: EXECUTIVE OVERVIEW
# ==========================================
with tab_overview:
    st.subheader("System Attack Surface & Defense Health")

    # Metric Cards Row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div style="color: #94a3b8; font-size: 13px;">HOLISTIC SYSTEM RISK</div>
                <div style="font-size: 32px; font-weight: bold; color: {"#ef4444" if risk_data["system_risk_score"] >= 50 else "#10b981"};">
                    {risk_data["system_risk_score"]} <span style="font-size: 18px; color: #94a3b8;">/ 100</span>
                </div>
                <small style="color: #94a3b8;">Probabilistic Crown Jewel Exposure</small>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        crit_count = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        st.markdown(
            f"""
            <div class="metric-card">
                <div style="color: #94a3b8; font-size: 13px;">ACTIVE FINDINGS</div>
                <div style="font-size: 32px; font-weight: bold; color: #f59e0b;">
                    {len(all_findings)}
                </div>
                <small style="color: #94a3b8;">{crit_count} Critical | {high_count} High</small>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c3:
        verif_count = sum(1 for v in verifications if v.decision.value == "VERIFIED")
        st.markdown(
            f"""
            <div class="metric-card">
                <div style="color: #94a3b8; font-size: 13px;">VERIFIED REMEDIATIONS</div>
                <div style="font-size: 32px; font-weight: bold; color: #10b981;">
                    {verif_count} <span style="font-size: 18px; color: #94a3b8;">/ {len(patches)}</span>
                </div>
                <small style="color: #94a3b8;">Deterministic Invariants Verified</small>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c4:
        audit_color = "#10b981" if audit_valid else "#ef4444"
        audit_text = "VALID & CHAINED" if audit_valid else "COMPROMISED"
        st.markdown(
            f"""
            <div class="metric-card">
                <div style="color: #94a3b8; font-size: 13px;">CRYPTOGRAPHIC AUDIT</div>
                <div style="font-size: 22px; font-weight: bold; color: {audit_color}; margin: 8px 0;">
                    {audit_text}
                </div>
                <small style="color: #94a3b8;">{audit_count} SHA-256 Chained Events</small>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    col_left, col_right = st.columns([1, 1])
    with col_left:
        st.markdown("### 🏆 Top Threat Trajectories Reaching Crown Jewels")
        if attack_paths:
            for p in attack_paths[:3]:
                st.markdown(
                    f"""
                    <div style="background: #1e293b; border-left: 4px solid #ef4444; padding: 12px 16px; margin-bottom: 10px; border-radius: 4px;">
                        <strong>Target:</strong> <code style="color: #ef4444;">{p.target_crown_jewel}</code> |
                        <strong>Probability:</strong> <code>{p.probability:.3f}</code> |
                        <strong>Risk:</strong> <code>{p.risk_contribution:.1f}</code><br>
                        <small style="color: #94a3b8;">{p.description}</small>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.success("Zero viable attack paths to crown jewels discovered.")

    with col_right:
        st.markdown("### 💎 Crown Jewel Asset Exposure Breakdown")
        jewel_data = risk_data.get("crown_jewel_risks", {})
        if jewel_data:
            for jewel, jdata in jewel_data.items():
                st.write(f"**{jewel}** (Criticality: `{jdata['criticality']:.2f}`)")
                prob = jdata["compromise_probability"]
                st.progress(
                    min(1.0, prob),
                    text=f"Compromise Probability: {prob:.1%} ({jdata['path_count']} paths)",
                )
        else:
            st.info("No crown jewels reachable from entry points.")


# ==========================================
# TAB 2: FINDINGS & PRIORITIZATION (RQ1)
# ==========================================
with tab_findings:
    st.subheader("Research Question 1 (RQ1): Contextual Risk Prioritization")
    st.markdown(
        "Demonstrates the multi-factor contextual risk scoring formula: "
        "$\\text{Score} = w_1 \\cdot \\text{CVSS} + w_2 \\cdot (\\text{EPSS} \\times 100) + w_3 \\cdot \\text{Reachability} + w_4 \\cdot \\text{Sensitivity}$ "
        "compared against baseline industry CVSS Base Scores."
    )

    if not ranked_findings:
        st.info("No findings currently in database.")
    else:
        # Table of findings
        display_data = []
        for idx, f in enumerate(ranked_findings, start=1):
            display_data.append(
                {
                    "Rank": idx,
                    "Finding ID": f.id,
                    "CWE": f.cwe,
                    "Title": f.title,
                    "Severity": f.severity.value,
                    "CVSS Base": f.cvss or 0.0,
                    "Contextual Score": round(f.contextual_score, 1) if f.contextual_score else 0.0,
                    "Rank Shift": "↑ Context Prioritized"
                    if (f.contextual_score or 0) > (f.cvss or 0) * 10
                    else "→ Consistent",
                    "Status": f.status.value,
                }
            )

        st.dataframe(display_data, use_container_width=True)

        st.markdown("### 🔍 Finding Threat Context Inspector")
        selected_id = st.selectbox(
            "Select finding to inspect LLM threat explanation & asset context:",
            [f.id for f in ranked_findings],
        )
        selected_finding = next((f for f in ranked_findings if f.id == selected_id), None)

        if selected_finding:
            c_info1, c_info2 = st.columns([1, 1])
            with c_info1:
                st.write(f"**Title:** {selected_finding.title}")
                st.write(f"**CWE:** `{selected_finding.cwe}` | **Tool:** `{selected_finding.tool}`")
                st.write(
                    f"**Target Location:** `{selected_finding.file or selected_finding.endpoint or 'N/A'}`"
                )
                st.write(
                    f"**CVSS v3.1:** `{selected_finding.cvss}` | **EPSS:** `{selected_finding.epss or 0.0}`"
                )
            with c_info2:
                st.write(
                    f"**Deterministic Contextual Risk:** `{selected_finding.contextual_score or 0.0:.1f} / 100`"
                )
                st.write(f"**Lifecycle Status:** `{selected_finding.status.value}`")
                if selected_finding.exploitability:
                    st.write(f"**Context Exposure:** {selected_finding.exploitability}")

            st.markdown("**LLM Grounded Threat Narrative:**")
            st.info(selected_finding.threat_context or selected_finding.description)


# ==========================================
# TAB 3: DIGITAL TWIN (RQ2)
# ==========================================
with tab_twin:
    st.subheader("Research Question 2 (RQ2): Digital Twin Attack Surface & Threat Paths")
    st.markdown(
        f"The Digital Twin models an in-memory NetworkX directed graph containing "
        f"**{twin.graph.number_of_nodes()} components** and **{twin.graph.number_of_edges()} relationships**."
    )

    t_col1, t_col2 = st.columns([1, 1])
    with t_col1:
        st.markdown("### 🕸️ Digital Twin Topology Flowchart")
        mermaid_code = twin.to_mermaid()
        st.markdown(f"```mermaid\n{mermaid_code}\n```")

    with t_col2:
        st.markdown("### 🗺️ Discovered Attack Trajectories")
        if attack_paths:
            for p in attack_paths:
                with st.expander(
                    f"Path {p.path_id}: ➔ {p.target_crown_jewel} (Prob: {p.probability:.3f}, Cost: {p.attacker_cost:.1f})"
                ):
                    st.write(f"**Probability:** `{p.probability:.4f}`")
                    st.write(f"**Attacker Effort:** `{p.attacker_cost:.1f}`")
                    st.write(f"**Risk Contribution:** `{p.risk_contribution:.1f} / 100`")
                    st.write(f"**Progression:** {p.description}")
                    st.write(f"**Exploited Findings:** {', '.join(p.exploited_findings) or 'None'}")
        else:
            st.success("Zero reachable attack paths.")


# ==========================================
# TAB 4: VERIFICATION & REMEDIATION
# ==========================================
with tab_remediation:
    st.subheader("Autonomous Remediation Engine & 4-Stage Deterministic Verification")
    st.markdown(
        "> **Core Safety Boundary:** Fixes are generated into an isolated Git sandbox (`.sentinel/sandbox/`). "
        "Patches are evaluated against functional unit tests and deterministic security invariants. "
        "The primary repository worktree is never modified until verification succeeds."
    )

    if not patches:
        st.info("No remediation patches generated yet.")
    else:
        patch_choices = [f"{p.id} ({p.finding_id} - {p.branch})" for p in patches]
        selected_p_str = st.selectbox(
            "Select patch to inspect verification evidence:", patch_choices
        )
        selected_p_id = selected_p_str.split(" ")[0]
        selected_patch = db.get_patch(selected_p_id)
        selected_verif = next((v for v in verifications if v.patch_id == selected_p_id), None)

        if selected_patch:
            p_col1, p_col2 = st.columns([1, 1])
            with p_col1:
                st.write(f"**Patch ID:** `{selected_patch.id}`")
                st.write(f"**Finding ID:** `{selected_patch.finding_id}`")
                st.write(f"**Sandbox Branch:** `{selected_patch.branch}`")
                st.write(f"**Attempt Number:** `{selected_patch.attempt}`")
            with p_col2:
                if selected_verif:
                    dec_val = selected_verif.decision.value
                    dec_color = "green" if dec_val == "VERIFIED" else "red"
                    st.markdown(f"**Verification Outcome:** :{dec_color}[**{dec_val}**]")
                else:
                    st.markdown("**Verification Outcome:** `PENDING`")

            # 4-stage checks display
            if selected_verif:
                st.markdown("#### 4-Stage Deterministic Verification Checklist:")
                chk1, chk2, chk3, chk4 = st.columns(4)
                with chk1:
                    u_status = "✅ PASS" if selected_verif.unit_passed else "❌ FAIL"
                    st.metric("1. Functional Tests", u_status)
                with chk2:
                    r_status = "✅ PASS" if selected_verif.regression_passed else "❌ FAIL"
                    st.metric("2. Security Invariants", r_status)
                with chk3:
                    f_status = (
                        "✅ ELIMINATED" if selected_verif.original_finding_gone else "❌ ACTIVE"
                    )
                    st.metric("3. Flaw Rescan", f_status)
                with chk4:
                    new_c = len(selected_verif.new_findings)
                    n_status = "✅ 0 NEW" if new_c == 0 else f"❌ {new_c} NEW"
                    st.metric("4. Side Effects", n_status)

            st.markdown("#### Unified Patch Diff:")
            st.code(selected_patch.diff or "# No diff available", language="diff")


# ==========================================
# TAB 5: COUNTERFACTUAL & RED/BLUE SIMULATION
# ==========================================
with tab_simulation:
    st.subheader("Research Question 3 (RQ3) & Phase 7: Simulation Engine")

    sim_col1, sim_col2 = st.columns([1, 1])
    with sim_col1:
        st.markdown("### 🎛️ Counterfactual Minimum Defensive Change (RQ3)")
        threshold = st.slider(
            "Target Risk Reduction Percentage (%)",
            min_value=10.0,
            max_value=90.0,
            value=40.0,
            step=5.0,
        )

        if st.button("Solve Minimum Defensive Cut", use_container_width=True):
            cf_sol = counterfactual_engine.evaluate_minimum_defensive_change(
                twin, target_reduction_pct=threshold
            )
            st.success(
                f"Optimal cut found: Drops risk from {cf_sol.pre_risk_score:.1f} to {cf_sol.post_risk_score:.1f} "
                f"(-{cf_sol.risk_reduction_pct:.1f}%) at operational cost {cf_sol.total_cost:.1f}."
            )
            for act in cf_sol.recommended_interventions:
                st.write(f"- **[{act.action_type}]** `{act.target_label}` (Cost: {act.cost:.1f})")

    with sim_col2:
        st.markdown("### ♟️ Turn-Based Red/Blue/Judge Simulation (Phase 7)")
        max_r = st.number_input("Max Game Rounds", min_value=1, max_value=10, value=5)
        seed_val = st.number_input(
            "Deterministic Random Seed", min_value=1, max_value=9999, value=42
        )

        if st.button("▶️ Execute In-Memory Simulation", use_container_width=True):
            sim_res = simulation_orchestrator.simulate(twin, max_rounds=max_r, seed=seed_val)
            st.markdown(f"**Winner:** **{sim_res.winner}**")
            st.markdown(
                f"**Risk Reduction:** `{sim_res.initial_risk_score:.1f} ➔ {sim_res.final_risk_score:.1f} (-{sim_res.total_risk_reduction_pct:.1f}%)`"
            )
            st.markdown(f"**Termination Reason:** {sim_res.stop_reason}")

            round_rows = []
            for r in sim_res.rounds:
                round_rows.append(
                    {
                        "Round": r.round_number,
                        "Red Target": r.red_move.targeted_crown_jewel if r.red_move else "None",
                        "Blue Defense": f"{r.blue_move.action_type} on {r.blue_move.target}"
                        if r.blue_move
                        else "None",
                        "Risk": f"{r.pre_round_risk:.1f} ➔ {r.post_round_risk:.1f}",
                        "Paths Left": r.paths_remaining,
                        "Displacement": f"⚠️ Displaced to {r.displaced_to}"
                        if r.path_displaced
                        else "None",
                    }
                )
            st.dataframe(round_rows, use_container_width=True)


# ==========================================
# TAB 6: REPORTS & AUDIT TRAIL
# ==========================================
with tab_reports:
    st.subheader("Audit Trail & Compliance Reports (Phase 8)")

    r_col1, r_col2 = st.columns([1, 1])
    with r_col1:
        st.markdown("### 🔗 Cryptographic Chained Audit Log (SHA-256)")
        st.write(f"**Log File:** `{audit_logger.log_path}`")
        st.write(
            f"**Status:** {'✅ VALID & UNTAMPERED' if audit_valid else f'❌ COMPROMISED: {audit_err}'}"
        )
        st.write(f"**Recorded Security Events:** `{audit_count}`")

        entries = audit_logger.read_all()
        if entries:
            with st.expander(f"View Recent Audit Events ({len(entries)} total)"):
                st.json(entries[-10:])

    with r_col2:
        st.markdown("### 📄 Export Full Security Audit Report")
        if st.button("Generate Markdown & HTML Reports", use_container_width=True):
            paths_dict = security_reporter.export_report()
            st.success(
                f"Reports saved successfully!\n- Markdown: {paths_dict['markdown']}\n- HTML: {paths_dict['html']}"
            )

        # Display raw markdown preview
        report_md = security_reporter.generate_markdown()
        with st.expander("Live Report Preview (Markdown)"):
            st.markdown(report_md)
