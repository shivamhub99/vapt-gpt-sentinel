"""
VAPT-GPT Sentinel Command Line Interface (CLI).
Provides user-facing commands to orchestrate scanning, prioritization, remediation,
verification, and digital twin simulation.
"""

from datetime import datetime, timezone
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
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
