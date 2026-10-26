"""
Unit and Integration Tests for Phase 8: Reporting Engine & Orchestration.
Validates:
1. Markdown report generation with all research artifacts (RQ1, RQ2, RQ3, Phase 7).
2. HTML report generation with styled CSS, badges, and responsive tables.
3. Exporting reports to filesystem.
4. Typer CLI commands 'sentinel report' and 'sentinel run'.
5. End-to-end closed-loop pipeline execution via SentinelOrchestrator.
"""

from pathlib import Path
from typing import List

import pytest
from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.core.orchestrator import FullRunResult, sentinel_orchestrator
from sentinel.core.reporter import SecurityReporter
from sentinel.core.schemas import Finding, Severity
from sentinel.core.scope_guard import ScopeViolationError


@pytest.fixture
def sample_findings() -> List[Finding]:
    return [
        Finding(
            id="rep_sqli_01",
            tool="bandit",
            cwe="CWE-89",
            title="SQL Injection in search API",
            severity=Severity.HIGH,
            cvss=8.5,
            epss=0.45,
            file="app.py",
            endpoint="/api/search",
        ),
        Finding(
            id="rep_secret_01",
            tool="gitleaks",
            cwe="CWE-798",
            title="Hardcoded API Secret",
            severity=Severity.CRITICAL,
            cvss=9.0,
            epss=0.60,
            file="app.py",
        ),
    ]


def test_reporter_markdown_generation():
    """Verifies that SecurityReporter generates valid Markdown with all research sections."""
    reporter = SecurityReporter()
    md = reporter.generate_markdown()

    assert "# VAPT-GPT Sentinel: Defensive Security & Closed-Loop Remediation Report" in md
    assert "## 1. Executive Summary" in md
    assert "## 2. Findings Inventory & Contextual Risk Prioritization (RQ1)" in md
    assert "## 3. Digital Twin Attack Surface & Threat Trajectories (RQ2)" in md
    assert "## 6. Deterministic Remediation & Verification Audit Trail" in md
    assert "## 7. Cryptographic Chained Audit Trail Verification" in md
    assert "Cryptographic Audit Chain Integrity" in md


def test_reporter_html_generation():
    """Verifies that SecurityReporter generates standalone valid HTML with modern styling."""
    reporter = SecurityReporter()
    html_out = reporter.generate_html()

    assert "<!DOCTYPE html>" in html_out
    assert '<html lang="en">' in html_out
    assert "VAPT-GPT Sentinel: Defensive Security & Remediation Report" in html_out
    assert "badge badge-" in html_out
    assert "kpi-grid" in html_out
    assert "</html>" in html_out


def test_reporter_export_files(tmp_path: Path):
    """Verifies that reports are correctly exported and written to disk."""
    reporter = SecurityReporter(output_dir=tmp_path)
    result = reporter.export_report(output_dir=tmp_path)

    assert "markdown" in result
    assert "html" in result

    md_file = result["markdown"]
    html_file = result["html"]

    assert md_file.exists()
    assert html_file.exists()
    assert md_file.stat().st_size > 500
    assert html_file.stat().st_size > 1000


def test_cli_report_command(tmp_path: Path):
    """Verifies the CLI command 'sentinel report' generates reports."""
    runner = CliRunner()
    result = runner.invoke(app, ["report", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0
    assert "Security Audit Report Generated Successfully!" in result.output
    assert (tmp_path / "sentinel_report_full_system.md").exists()
    assert (tmp_path / "sentinel_report_full_system.html").exists()


def test_orchestrator_pipeline_execution():
    """Verifies that the autonomous orchestrator executes the full closed-loop pipeline."""
    result = sentinel_orchestrator.run_pipeline(
        target="http://localhost:8080",
        auto_fix=False,
        auto_verify=False,
    )

    assert isinstance(result, FullRunResult)
    assert result.target == "http://localhost:8080"
    assert result.initial_system_risk >= 0.0
    assert result.residual_system_risk >= 0.0
    assert result.total_findings_count >= 1
    assert "markdown" in result.report_paths
    assert "html" in result.report_paths
    assert Path(result.report_paths["markdown"]).exists()


def test_orchestrator_rejects_out_of_scope():
    """Verifies the safety boundary: out-of-scope targets are rejected before scanning."""
    with pytest.raises(ScopeViolationError):
        sentinel_orchestrator.run_pipeline(
            target="http://198.51.100.1:8080",
            auto_fix=False,
            auto_verify=False,
        )
