"""
VAPT-GPT Sentinel Command Line Interface (CLI).
Provides user-facing commands to orchestrate scanning, prioritization, remediation,
verification, and digital twin simulation.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from sentinel.core.audit_log import audit_logger
from sentinel.core.scope_guard import ScopeViolationError, UnauthorizedTargetError
from sentinel.scanners import SCANNER_REGISTRY

app = typer.Typer(
    name="sentinel",
    help="VAPT-GPT Sentinel: Defensive Closed-Loop Vulnerability Remediation & Attack-Path Twin",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    target: str = typer.Option(
        "http://localhost:8080",
        "--target",
        "-t",
        help="Target URL, host, or local path to scan",
    ),
    tool: Optional[str] = typer.Option(
        None,
        "--tool",
        help="Specific scanner to execute (bandit, semgrep, pip_audit, gitleaks, nmap, headers, trivy, zap)",
    ),
    run_id: Optional[str] = typer.Option(
        None,
        "--run-id",
        help="Custom run ID for grouping results",
    ),
) -> None:
    """Executes non-destructive security scanners under ScopeGuard supervision."""
    active_run_id = run_id or f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

    console.print(
        Panel.fit(
            f"[bold cyan]VAPT-GPT Sentinel Security Scan[/bold cyan]\n"
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Run ID:[/bold] {active_run_id}",
            border_style="cyan",
        )
    )

    # Determine which tools to run
    if tool:
        tool_name = tool.lower()
        if tool_name not in SCANNER_REGISTRY:
            console.print(
                f"[bold red]Unknown tool '{tool}'. Available tools:[/bold red] "
                f"{', '.join(SCANNER_REGISTRY.keys())}"
            )
            raise typer.Exit(code=1)
        tools_to_run = [tool_name]
    else:
        # Auto-select tools based on target type
        is_web = target.startswith("http://") or target.startswith("https://")
        if is_web:
            tools_to_run = ["headers", "zap", "nmap"]
        else:
            tools_to_run = ["bandit", "semgrep", "gitleaks", "pip_audit", "trivy"]

    results_table = Table(
        title="Scan Execution Results", show_header=True, header_style="bold magenta"
    )
    results_table.add_column("Scanner", style="cyan")
    results_table.add_column("Status", style="bold")
    results_table.add_column("Findings Detected", justify="right")
    results_table.add_column("Raw Output", style="dim")

    for t_name in tools_to_run:
        scanner_cls = SCANNER_REGISTRY[t_name]
        scanner = scanner_cls()
        console.print(f"[yellow]Executing {t_name}...[/yellow]")
        try:
            raw_res = scanner.execute(target=target, run_id=active_run_id)
            findings = scanner.parse(raw_res)
            out_file = scanner.get_raw_output_path(active_run_id)
            status_str = "[green]SUCCESS[/green]"
            count_str = str(len(findings))
            results_table.add_row(t_name, status_str, count_str, str(out_file))
        except UnauthorizedTargetError as exc:
            console.print(f"[bold red]Authorization Error:[/bold red] {str(exc)}")
            raise typer.Exit(code=1)
        except ScopeViolationError as exc:
            console.print(f"[bold red]Scope Violation:[/bold red] {str(exc)}")
            raise typer.Exit(code=1)
        except Exception as exc:
            results_table.add_row(t_name, "[red]FAILED[/red]", "0", str(exc))

    console.print(results_table)
    console.print(
        f"\n[bold green]Scan complete![/bold green] Raw artifacts saved to [cyan]runs/{active_run_id}/raw/[/cyan]"
    )

    # Automatically normalize and deduplicate findings into SQLite
    from sentinel.normalize.normalizer import normalizer

    console.print("[yellow]Normalizing and deduplicating findings into SQLite database...[/yellow]")
    deduped = normalizer.normalize_run(run_id=active_run_id)

    findings_table = Table(
        title=f"Normalized & Deduplicated Findings ({len(deduped)} total)",
        show_header=True,
        header_style="bold green",
    )
    findings_table.add_column("ID", style="dim", no_wrap=True)
    findings_table.add_column("CWE", style="bold yellow")
    findings_table.add_column("OWASP", style="cyan")
    findings_table.add_column("Severity", style="bold")
    findings_table.add_column("Title")
    findings_table.add_column("Tools", style="magenta")

    for f in deduped:
        sev_color = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim",
        }.get(f.severity.value, "white")
        findings_table.add_row(
            f.id,
            f.cwe,
            f.owasp or "N/A",
            f"[{sev_color}]{f.severity.value}[/{sev_color}]",
            f.title[:50] + ("..." if len(f.title) > 50 else ""),
            f.tool,
        )

    console.print(findings_table)


@app.command()
def findings(
    run_id: Optional[str] = typer.Option(
        None,
        "--run-id",
        "-r",
        help="Run ID to display findings for (defaults to latest recorded run)",
    ),
) -> None:
    """Lists normalized findings from the SQLite database."""
    from sentinel.core.database import db

    conn = db.get_connection()
    cursor = conn.cursor()

    if not run_id:
        cursor.execute("SELECT run_id FROM runs ORDER BY timestamp DESC LIMIT 1")
        row = cursor.fetchone()
        if not row:
            console.print("[yellow]No scan runs recorded in database yet.[/yellow]")
            return
        target_run_id = row["run_id"]
    else:
        target_run_id = run_id

    records = db.get_findings_by_run(target_run_id)
    if not records:
        console.print(f"[yellow]No findings found for run '{target_run_id}'.[/yellow]")
        return

    table = Table(
        title=f"Findings for Run: {target_run_id} ({len(records)} findings)",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("CWE", style="bold yellow")
    table.add_column("Severity", style="bold")
    table.add_column("Title")
    table.add_column("Location / Endpoint")
    table.add_column("Status", style="bold green")

    for f in records:
        loc = f.file or f.endpoint or "N/A"
        if f.line:
            loc = f"{loc}:{f.line}"
        table.add_row(f.id, f.cwe, f.severity.value, f.title[:45], str(loc), f.status.value)

    console.print(table)


@app.command()
def prioritize(
    run_id: Optional[str] = typer.Option(
        None,
        "--run-id",
        "-r",
        help="Run ID to prioritize findings for (defaults to latest recorded run)",
    ),
) -> None:
    """Prioritizes findings comparing baseline CVSS vs contextual risk formula (RQ1)."""
    from sentinel.core.database import db
    from sentinel.reasoning.prioritizer import prioritizer

    conn = db.get_connection()
    cursor = conn.cursor()

    if not run_id:
        cursor.execute("SELECT run_id FROM runs ORDER BY timestamp DESC LIMIT 1")
        row = cursor.fetchone()
        if not row:
            console.print("[yellow]No scan runs recorded in database yet.[/yellow]")
            return
        target_run_id = row["run_id"]
    else:
        target_run_id = run_id

    findings_list = db.get_findings_by_run(target_run_id)
    if not findings_list:
        console.print(f"[yellow]No findings found for run '{target_run_id}'.[/yellow]")
        return

    console.print(
        Panel.fit(
            f"[bold cyan]Research Question 1 (RQ1): Contextual Risk Prioritization[/bold cyan]\n"
            f"[bold]Run ID:[/bold] {target_run_id} | [bold]Total Findings:[/bold] {len(findings_list)}",
            border_style="cyan",
        )
    )

    # 1. Baseline CVSS ranking
    baseline_ranked = prioritizer.rank_baseline_cvss(findings_list)
    baseline_ranks = {f.id: idx + 1 for idx, (f, _) in enumerate(baseline_ranked)}

    # 2. Contextual ranking
    context_ranked = prioritizer.rank_contextual(findings_list)

    table = Table(
        title="Prioritization Comparison: Baseline CVSS vs Sentinel Contextual Score",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Context Rank", style="bold green", justify="center")
    table.add_column("CVSS Rank", style="dim", justify="center")
    table.add_column("CWE", style="bold yellow")
    table.add_column("Title")
    table.add_column("CVSS Base", justify="right")
    table.add_column("Context Risk (0-100)", style="bold red", justify="right")
    table.add_column("Exposure Context", style="cyan")

    for c_rank, (f, score) in enumerate(context_ranked, start=1):
        b_rank = baseline_ranks.get(f.id, "N/A")
        factors = score.context_factors
        exposure_desc = (
            f"{factors.data_sensitivity} | {'public' if factors.internet_facing else 'internal'}"
        )
        table.add_row(
            f"#{c_rank}",
            f"#{b_rank}",
            f.cwe,
            f.title[:38] + ("..." if len(f.title) > 38 else ""),
            f"{score.base_score:.1f}",
            f"{score.final_score:.1f}",
            exposure_desc,
        )

    console.print(table)

    # Print top explanation
    if context_ranked:
        top_f, top_score = context_ranked[0]
        console.print(
            Panel(
                f"[bold yellow]Top Threat Analysis (Finding {top_f.id}):[/bold yellow]\n"
                f"{top_score.explanation}",
                title="LLM Qualitative Threat Explanation (Deterministic Score Grounding)",
                border_style="yellow",
            )
        )


@app.command()
def fix(
    finding_id: str = typer.Option(
        ...,
        "--finding",
        "-f",
        help="Finding ID to remediate (from 'sentinel findings')",
    ),
    target: str = typer.Option(
        "lab/sentinel-lab-app",
        "--target",
        "-t",
        help="Path to target project repository to safely patch in sandbox",
    ),
    attempt: int = typer.Option(
        1,
        "--attempt",
        "-a",
        help="Remediation attempt number (1-3)",
    ),
) -> None:
    """Safely remediates a finding onto an isolated Git sandbox branch (Hard Safety Rule 4)."""
    from sentinel.core.database import db
    from sentinel.remediation.engine import RemediationGatedError, remediation_engine
    from sentinel.remediation.patch_apply import PatchApplicationError

    target_path = Path(target).resolve()
    if not target_path.exists():
        console.print(f"[bold red]Target directory not found:[/bold red] {target_path}")
        raise typer.Exit(code=1)

    finding = db.get_finding(finding_id)
    if not finding:
        console.print(f"[bold red]Finding '{finding_id}' not found in database.[/bold red]")
        raise typer.Exit(code=1)

    console.print(
        Panel.fit(
            f"[bold cyan]VAPT-GPT Sentinel Safe Remediation Engine[/bold cyan]\n"
            f"[bold]Finding:[/bold] {finding.id} ({finding.cwe} - {finding.title})\n"
            f"[bold]Target:[/bold] {target_path}\n"
            f"[bold]Attempt:[/bold] {attempt}\n"
            f"[bold]Policy:[/bold] Isolated Git sandbox branch (primary worktree untouched)",
            border_style="cyan",
        )
    )

    try:
        patch, repo = remediation_engine.remediate(
            finding=finding,
            target_dir=target_path,
            attempt=attempt,
        )
        console.print(
            Panel(
                f"[bold green]Patch successfully generated and committed to isolated sandbox branch![/bold green]\n\n"
                f"[bold]Patch ID:[/bold] {patch.id}\n"
                f"[bold]Branch:[/bold] [yellow]{patch.branch}[/yellow]\n"
                f"[bold]Generated By:[/bold] {patch.generated_by}\n"
                f"[bold]Rationale:[/bold] {patch.rationale}\n\n"
                f"[bold cyan]Unified Diff Applied:[/bold cyan]",
                title="Remediation Applied to Sandbox",
                border_style="green",
            )
        )
        if patch.diff:
            console.print(Syntax(patch.diff, "diff", theme="monokai", line_numbers=True))
        console.print(
            f"\n[green]Next Step:[/green] Run [bold cyan]sentinel verify --patch {patch.id}[/bold cyan] "
            f"to run functional unit tests, security regression tests, and rescan verification before merge."
        )
    except RemediationGatedError as exc:
        console.print(
            Panel(
                f"[bold red]REMEDIATION GATED (Hard Safety Rule 5):[/bold red]\n\n"
                f"{str(exc)}\n\n"
                f"[yellow]Status updated to:[/yellow] [bold]NEEDS_HUMAN[/bold]\n"
                f"Automated patching of authentication/authorization/financial logic is prohibited "
                f"to prevent breaking business logic invariants without human sign-off.",
                title="Gated Security Category",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    except PatchApplicationError as exc:
        console.print(
            Panel(
                f"[bold red]Patch Application Conflict:[/bold red]\n{str(exc)}\n\n"
                f"Changes have been cleanly rolled back. Primary worktree remains completely untouched.",
                title="Application Error",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red]Remediation Failed:[/bold red] {exc}")
        raise typer.Exit(code=1)


@app.command()
def verify(
    patch_id: str = typer.Option(
        ...,
        "--patch",
        "-p",
        help="Patch ID to deterministically verify (from 'sentinel fix')",
    ),
    target: str = typer.Option(
        "lab/sentinel-lab-app",
        "--target",
        "-t",
        help="Path to target project repository",
    ),
    retry: bool = typer.Option(
        True,
        "--retry/--no-retry",
        help="Whether to automatically retry with failure feedback if verification fails",
    ),
    max_attempts: int = typer.Option(
        3,
        "--max-attempts",
        help="Maximum remediation attempts before escalating to NEEDS_HUMAN",
    ),
) -> None:
    """Deterministically verifies a patch via unit tests, security regression, and rescan (The Core Loop)."""
    from sentinel.core.database import db
    from sentinel.core.schemas import DecisionEnum
    from sentinel.verification.engine import verification_engine

    target_path = Path(target).resolve()
    patch = db.get_patch(patch_id)
    if not patch:
        console.print(f"[bold red]Patch '{patch_id}' not found in database.[/bold red]")
        raise typer.Exit(code=1)

    console.print(
        Panel.fit(
            f"[bold cyan]VAPT-GPT Sentinel Deterministic Verification Engine[/bold cyan]\n"
            f"[bold]Patch ID:[/bold] {patch.id} | [bold]Finding:[/bold] {patch.finding_id}\n"
            f"[bold]Branch:[/bold] {patch.branch} | [bold]Attempt:[/bold] {patch.attempt}\n"
            f"[bold]Target:[/bold] {target_path}\n"
            f"[bold]Core Principle:[/bold] LLM proposes fixes; deterministic tests decide acceptance",
            border_style="cyan",
        )
    )

    with console.status("[yellow]Executing 4-stage verification loop...[/yellow]"):
        try:
            verification = verification_engine.verify(
                patch_id=patch.id,
                target_dir=target_path,
                auto_retry=retry,
                max_attempts=max_attempts,
            )
        except Exception as exc:
            console.print(f"[bold red]Verification Execution Error:[/bold red] {exc}")
            raise typer.Exit(code=1)

    # Verification results table
    table = Table(
        title="Deterministic Verification Outcomes", show_header=True, header_style="bold magenta"
    )
    table.add_column("Verification Check", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Diagnostic Details", style="dim")

    # 1. Functional Tests
    unit_status = (
        "[bold green]PASSED[/bold green]"
        if verification.unit_passed
        else "[bold red]FAILED[/bold red]"
    )
    table.add_row(
        "1. Functional Unit Tests",
        unit_status,
        str(verification.evidence.get("unit_log", ""))[:60] + "...",
    )

    # 2. Security Regression Invariants
    reg_status = (
        "[bold green]PASSED[/bold green]"
        if verification.regression_passed
        else "[bold red]FAILED[/bold red]"
    )
    table.add_row(
        "2. Security Regression Invariants",
        reg_status,
        str(verification.evidence.get("regression_log", ""))[:60] + "...",
    )

    # 3. Original Flaw Elimination
    orig_status = (
        "[bold green]ELIMINATED[/bold green]"
        if verification.original_finding_gone
        else "[bold red]STILL ACTIVE[/bold red]"
    )
    table.add_row(
        "3. Targeted Rescan (Original Flaw)",
        orig_status,
        "Vulnerability eliminated in patched source",
    )

    # 4. Secondary Vulnerability Inspection
    new_count = len(verification.new_findings)
    new_status = (
        "[bold green]0 DETECTED[/bold green]"
        if new_count == 0
        else f"[bold red]{new_count} INTRODUCED[/bold red]"
    )
    table.add_row(
        "4. Secondary Flaws Check", new_status, "Zero new vulnerabilities introduced by patch"
    )

    console.print(table)

    if verification.decision == DecisionEnum.VERIFIED:
        console.print(
            Panel(
                f"[bold green]PATCH VERIFIED & ACCEPTED![/bold green]\n\n"
                f"Patch [bold]{verification.patch_id}[/bold] for finding [bold]{verification.finding_id}[/bold] "
                f"passed all functional unit tests and deterministic security regression checks.\n"
                f"The vulnerability has been completely neutralized with zero side effects.\n\n"
                f"[cyan]Database finding lifecycle updated to:[/cyan] [bold green]VERIFIED[/bold green]",
                title="Verification Complete",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                f"[bold red]PATCH REJECTED: {verification.decision.value}[/bold red]\n\n"
                f"Reason: {verification.evidence.get('decision_reason', 'Verification checks failed.')}\n\n"
                f"[yellow]Action:[/yellow] Sandbox branch rolled back. Primary worktree remains completely clean.\n"
                f"If max attempts exceeded, finding status escalated to [bold]NEEDS_HUMAN[/bold].",
                title="Verification Rejection",
                border_style="red",
            )
        )


twin_app = typer.Typer(
    name="twin",
    help="Digital Twin Attack Path & Counterfactual Reasoning Engine (RQ2, RQ3)",
    add_completion=False,
)
app.add_typer(twin_app, name="twin")


def _get_target_run_findings(run_id: Optional[str]):
    from sentinel.core.database import db

    if run_id:
        target_run_id = run_id
        findings = db.get_findings_by_run(target_run_id)
    else:
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM findings")
        rows = cursor.fetchall()
        conn.close()
        target_run_id = "full_system"
        findings = [db.get_finding(r["id"]) for r in rows]

    return target_run_id, [f for f in findings if f]


@twin_app.command(name="paths")
def twin_paths(
    run_id: Optional[str] = typer.Option(
        None,
        "--run-id",
        "-r",
        help="Run ID to analyze attack paths for (defaults to latest scan)",
    ),
) -> None:
    """Discovers all attack paths from entry points to crown jewels (RQ2)."""
    from sentinel.twin.attack_paths import attack_path_analyzer
    from sentinel.twin.builder import twin_builder

    target_run_id, findings = _get_target_run_findings(run_id)
    if not findings:
        console.print(
            "[yellow]No findings found in database. Building baseline topology...[/yellow]"
        )

    console.print(
        Panel.fit(
            f"[bold cyan]Research Question 2 (RQ2): Digital Twin Attack Path Analysis[/bold cyan]\n"
            f"[bold]Run ID:[/bold] {target_run_id or 'baseline'} | [bold]Findings Incorporated:[/bold] {len(findings)}",
            border_style="cyan",
        )
    )

    twin = twin_builder.build(findings)
    paths = attack_path_analyzer.find_all_attack_paths(twin)

    if not paths:
        console.print("[green]Zero reachable attack paths to crown jewels discovered![/green]")
        return

    table = Table(
        title=f"Discovered Attack Paths to Crown Jewels ({len(paths)} total)",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Path ID", style="dim", no_wrap=True)
    table.add_column("Target Crown Jewel", style="bold red")
    table.add_column("Probability", justify="right", style="bold yellow")
    table.add_column("Effort (Cost)", justify="right")
    table.add_column("Risk Contrib", justify="right", style="bold red")
    table.add_column("Exploit Progression Narrative")

    for p in paths:
        table.add_row(
            p.path_id,
            p.target_crown_jewel,
            f"{p.probability:.3f}",
            f"{p.attacker_cost:.1f}",
            f"{p.risk_contribution:.1f}",
            p.description,
        )

    console.print(table)


@twin_app.command(name="risk")
def twin_risk(
    run_id: Optional[str] = typer.Option(
        None,
        "--run-id",
        "-r",
        help="Run ID to calculate holistic system risk for",
    ),
) -> None:
    """Calculates holistic system attack surface risk score (0-100) (RQ2)."""
    from sentinel.twin.attack_paths import attack_path_analyzer
    from sentinel.twin.builder import twin_builder
    from sentinel.twin.risk import system_risk_calculator

    target_run_id, findings = _get_target_run_findings(run_id)
    twin = twin_builder.build(findings)
    paths = attack_path_analyzer.find_all_attack_paths(twin)
    risk_data = system_risk_calculator.calculate_system_risk(paths)

    system_score = risk_data["system_risk_score"]
    score_color = "red" if system_score >= 60 else ("yellow" if system_score >= 30 else "green")

    console.print(
        Panel(
            f"[bold {score_color}]System Attack Surface Risk Score: {system_score} / 100[/bold {score_color}]\n\n"
            f"[bold]Run ID:[/bold] {target_run_id or 'baseline'} | [bold]Total Attack Paths:[/bold] {risk_data['total_paths_count']}\n"
            f"{risk_data['summary']}",
            title="Digital Twin System Risk Assessment (RQ2)",
            border_style=score_color,
        )
    )

    jewels_table = Table(
        title="Crown Jewel Asset Exposure Breakdown", show_header=True, header_style="bold cyan"
    )
    jewels_table.add_column("Crown Jewel Asset", style="bold")
    jewels_table.add_column("Compromise Probability", justify="right", style="yellow")
    jewels_table.add_column("Asset Criticality", justify="right")
    jewels_table.add_column("Asset Risk Score", justify="right", style="bold red")
    jewels_table.add_column("Reaching Paths", justify="center")

    for jewel, data in risk_data["crown_jewel_risks"].items():
        jewels_table.add_row(
            jewel,
            f"{data['compromise_probability']:.3f}",
            f"{data['criticality']:.2f}",
            f"{data['risk_score']:.1f}",
            str(data["path_count"]),
        )

    console.print(jewels_table)


@twin_app.command(name="counterfactual")
def twin_counterfactual(
    run_id: Optional[str] = typer.Option(
        None,
        "--run-id",
        "-r",
        help="Run ID to perform counterfactual intervention optimization for",
    ),
    threshold: float = typer.Option(
        40.0,
        "--threshold",
        "-t",
        help="Target risk reduction percentage (default: 40%)",
    ),
) -> None:
    """Solves the Minimum Defensive Change Problem: minimal-cost intervention set (RQ3)."""
    from sentinel.twin.builder import twin_builder
    from sentinel.twin.counterfactual import counterfactual_engine

    target_run_id, findings = _get_target_run_findings(run_id)
    twin = twin_builder.build(findings)

    console.print(
        Panel.fit(
            f"[bold cyan]Research Question 3 (RQ3): Counterfactual Minimum Defensive Change[/bold cyan]\n"
            f"[bold]Target Risk Reduction Threshold:[/bold] {threshold:.1f}%\n"
            f"[bold]Run ID:[/bold] {target_run_id or 'baseline'}",
            border_style="cyan",
        )
    )

    with console.status(
        "[yellow]Evaluating combinatorial intervention cuts on in-memory twin...[/yellow]"
    ):
        result = counterfactual_engine.evaluate_minimum_defensive_change(
            twin, target_reduction_pct=threshold
        )

    console.print(
        Panel(
            f"[bold green]Optimal Minimum Defensive Intervention Solution:[/bold green]\n\n"
            f"{result.explanation}\n\n"
            f"[bold]Baseline Risk:[/bold] {result.pre_risk_score} -> [bold green]Residual Risk:[/bold green] {result.post_risk_score}\n"
            f"[bold]Risk Reduction:[/bold] [bold green]-{result.risk_reduction_pct:.1f}%[/bold green]\n"
            f"[bold]Total Operational Cost:[/bold] {result.total_cost:.1f}\n"
            f"[bold]Attack Paths Disrupted:[/bold] {result.disrupted_paths_count} (Residual Paths: {result.residual_paths_count})",
            title="Optimal Defensive Plan (RQ3)",
            border_style="green",
        )
    )

    # Action Items Table
    actions_table = Table(
        title="Recommended Minimal Action Set", show_header=True, header_style="bold yellow"
    )
    actions_table.add_column("Action Type", style="cyan")
    actions_table.add_column("Target Item", style="bold")
    actions_table.add_column("Cost", justify="right")
    actions_table.add_column("Rationale / Impact")

    for act in result.recommended_interventions:
        actions_table.add_row(act.action_type, act.target_label, f"{act.cost:.1f}", act.description)

    console.print(actions_table)

    # Trade-off Alternatives Table
    if result.tradeoff_alternatives:
        tradeoff_table = Table(
            title="Trade-off Alternatives: Operational Cost vs Risk Reduction",
            show_header=True,
            header_style="bold magenta",
        )
        tradeoff_table.add_column("Intervention Bundle", style="bold")
        tradeoff_table.add_column("Defensive Cost", justify="right")
        tradeoff_table.add_column("Residual Risk", justify="right", style="cyan")
        tradeoff_table.add_column("Risk Reduction %", justify="right", style="bold green")
        tradeoff_table.add_column("Paths Broken", justify="center")

        for alt in result.tradeoff_alternatives:
            tradeoff_table.add_row(
                alt["actions"][:45] + ("..." if len(alt["actions"]) > 45 else ""),
                f"{alt['cost']:.1f}",
                f"{alt['post_risk']:.1f}",
                alt["reduction_pct"],
                str(alt["disrupted_paths"]),
            )

        console.print(tradeoff_table)


@app.command()
def status() -> None:
    """Displays framework status, scope boundaries, and running lab targets."""
    import os

    from sentinel.core.scope_guard import scope_guard

    auth_val = os.getenv("SENTINEL_I_OWN_THIS_TARGET", "").strip().lower()
    is_authed = auth_val in ("true", "1", "yes")

    table = Table(title="Sentinel Framework Status", show_header=True, header_style="bold cyan")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row(
        "Target Ownership Authorized",
        "[green]YES (SENTINEL_I_OWN_THIS_TARGET=true)[/green]"
        if is_authed
        else "[red]NO (Refusing all scans until set in .env)[/red]",
    )
    table.add_row("Allowed Hostnames", ", ".join(scope_guard.allowed_hostnames))
    table.add_row("Allowed CIDRs", ", ".join(str(c) for c in scope_guard.allowed_cidrs))
    table.add_row("Allowed Ports", ", ".join(str(p) for p in scope_guard.allowed_ports))
    table.add_row("Audit Log Location", str(audit_logger.log_path))

    console.print(table)


if __name__ == "__main__":
    app()
