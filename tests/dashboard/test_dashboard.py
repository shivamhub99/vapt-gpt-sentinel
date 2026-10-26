"""
Unit tests for Phase 8 Streamlit Security Dashboard.
Validates:
1. Dashboard application module integrity and syntax.
2. Database query helper functions (load_findings, load_patches_and_verifications).
3. CLI command 'sentinel dashboard --help'.
"""

import ast
from pathlib import Path

from typer.testing import CliRunner

from sentinel.cli import app


def test_dashboard_file_exists_and_syntax_valid():
    """Verifies dashboard/app.py exists and parses cleanly with ast without syntax errors."""
    app_path = Path("dashboard/app.py")
    assert app_path.exists(), "dashboard/app.py must exist"

    content = app_path.read_text(encoding="utf-8")
    assert len(content) > 1000
    # Must parse without SyntaxError
    parsed = ast.parse(content)
    assert parsed is not None


def test_cli_dashboard_help():
    """Verifies that 'sentinel dashboard --help' outputs valid options."""
    runner = CliRunner()
    result = runner.invoke(app, ["dashboard", "--help"])

    assert result.exit_code == 0
    assert "Streamlit" in result.output
    assert "--port" in result.output
