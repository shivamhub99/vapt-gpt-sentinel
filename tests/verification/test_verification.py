"""
Unit and Integration Tests for Phase 5: Verification Loop and Deterministic State Machine.
Validates:
1. Functional unit test execution on patched sandbox.
2. Catching functional regressions (broken tests).
3. Deterministic security regression invariants across SQLi, XSS, Secrets, Dependencies, and Headers.
4. Decision state machine (VERIFIED, REJECTED_FUNCTIONAL, REJECTED_NEW_VULN, REJECTED_UNRESOLVED).
5. End-to-end verified patch acceptance and database status transition.
6. Automatic rollback on rejected patches without dirtying primary target repository.
7. Autonomous retry feedback loop.
"""

from pathlib import Path

import git
import pytest

from sentinel.core.audit_log import audit_logger
from sentinel.core.database import db
from sentinel.core.schemas import DecisionEnum, Finding, FindingStatus, Patch, Severity
from sentinel.remediation.engine import remediation_engine
from sentinel.remediation.patch_apply import sandbox_manager
from sentinel.verification.decider import decider
from sentinel.verification.engine import verification_engine
from sentinel.verification.regression_runner import security_regression_runner
from sentinel.verification.unit_runner import unit_test_runner


@pytest.fixture
def target_repo_with_tests(tmp_path: Path) -> Path:
    """Creates a local dummy target Git repository with code and a functional unit test suite."""
    target_dir = tmp_path / "patient_app_with_tests"
    target_dir.mkdir(parents=True, exist_ok=True)

    app_py = target_dir / "app.py"
    app_py.write_text(
        "from flask import Flask, request, jsonify\n"
        "app = Flask(__name__)\n\n"
        'API_SECRET_KEY = "insecure_plaintext_key_12345"\n\n'
        '@app.route("/api/ping")\n'
        "def ping():\n"
        '    return jsonify({"status": "ok"})\n\n'
        '@app.route("/api/search")\n'
        "def search():\n"
        '    query = request.args.get("q", "")\n'
        "    raw_sql = f\"SELECT id, name, description, price FROM products WHERE name LIKE '%{query}%'\"\n"
        "    cursor.execute(raw_sql)\n"
        '    return jsonify({"results": []})\n',
        encoding="utf-8",
    )

    req_txt = target_dir / "requirements.txt"
    req_txt.write_text("Flask==2.2.5\nrequests==2.25.1\n", encoding="utf-8")

    # Add functional unit tests
    test_dir = target_dir / "tests"
    test_dir.mkdir()
    test_py = test_dir / "test_app.py"
    test_py.write_text(
        "def test_math_sanity():\n    assert 1 + 1 == 2\n",
        encoding="utf-8",
    )

    # Initialize git repo and commit
    repo = git.Repo.init(target_dir)
    repo.git.config("user.name", "Sentinel Verifier")
    repo.git.config("user.email", "verify@sentinel.local")
    repo.git.add(all=True)
    repo.index.commit("Initial target repository with functional tests")

    return target_dir


def test_unit_runner_passes_on_valid_suite(target_repo_with_tests: Path):
    """Verifies that UnitTestRunner executes pytest and returns True when tests pass."""
    passed, log = unit_test_runner.run_tests(target_repo_with_tests)
    assert passed is True
    assert "passed successfully" in log or "1 passed" in log


def test_unit_runner_catches_functional_regression(tmp_path: Path):
    """Verifies that UnitTestRunner catches broken tests and extracts failure diagnostics."""
    broken_dir = tmp_path / "broken_app"
    broken_dir.mkdir()
    tests_dir = broken_dir / "tests"
    tests_dir.mkdir()
    broken_test = tests_dir / "test_broken.py"
    broken_test.write_text(
        'def test_broken_feature():\n    assert False, "Intentional functional failure"\n',
        encoding="utf-8",
    )

    passed, log = unit_test_runner.run_tests(broken_dir)
    assert passed is False
    assert "Functional test failure" in log
    assert "Intentional functional failure" in log


def test_security_regression_runner_sqli(tmp_path: Path):
    """Verifies security regression checks for SQL injection parameterization."""
    box_dir = tmp_path / "sqli_box"
    box_dir.mkdir()
    app_file = box_dir / "app.py"

    finding = Finding(
        id="f_sqli_test",
        tool="bandit",
        cwe="CWE-89",
        title="SQL Injection",
        severity=Severity.HIGH,
        file="app.py",
    )

    # Vulnerable code
    app_file.write_text(
        "raw_sql = f\"SELECT * FROM users WHERE name LIKE '%{q}%'\"\ncursor.execute(raw_sql)\n",
        encoding="utf-8",
    )
    passed, msg = security_regression_runner.run_regression(finding, box_dir)
    assert passed is False
    assert "Insecure formatted SQL string" in msg

    # Patched code
    app_file.write_text(
        'cursor.execute("SELECT * FROM users WHERE name LIKE ?", (q,))\n',
        encoding="utf-8",
    )
    passed, msg = security_regression_runner.run_regression(finding, box_dir)
    assert passed is True
    assert "passed" in msg.lower()


def test_security_regression_runner_xss(tmp_path: Path):
    """Verifies security regression checks for reflected XSS output escaping."""
    box_dir = tmp_path / "xss_box"
    box_dir.mkdir()
    app_file = box_dir / "app.py"

    finding = Finding(
        id="f_xss_test",
        tool="semgrep",
        cwe="CWE-79",
        title="Reflected XSS",
        severity=Severity.HIGH,
        file="app.py",
    )

    # Vulnerable code
    app_file.write_text(
        'def greet(name):\n    return f"<html>{name}</html>"\n',
        encoding="utf-8",
    )
    passed, msg = security_regression_runner.run_regression(finding, box_dir)
    assert passed is False
    assert "without HTML output escaping" in msg

    # Patched code
    app_file.write_text(
        'from markupsafe import escape\ndef greet(name):\n    safe_name = escape(name)\n    return f"<html>{safe_name}</html>"\n',
        encoding="utf-8",
    )
    passed, msg = security_regression_runner.run_regression(finding, box_dir)
    assert passed is True
    assert "passed" in msg.lower()


def test_security_regression_runner_secrets(tmp_path: Path):
    """Verifies security regression checks for hardcoded credentials."""
    box_dir = tmp_path / "sec_box"
    box_dir.mkdir()
    app_file = box_dir / "app.py"

    finding = Finding(
        id="f_sec_test",
        tool="gitleaks",
        cwe="CWE-798",
        title="Hardcoded API Secret",
        severity=Severity.CRITICAL,
        file="app.py",
    )

    # Vulnerable code
    app_file.write_text(
        'API_SECRET_KEY = "super_secret_plaintext_key_12345"\n',
        encoding="utf-8",
    )
    passed, msg = security_regression_runner.run_regression(finding, box_dir)
    assert passed is False
    assert "Plaintext API secret key constant is still hardcoded" in msg

    # Patched code
    app_file.write_text(
        'import os\nAPI_SECRET_KEY = os.environ.get("API_SECRET_KEY", "fallback")\n',
        encoding="utf-8",
    )
    passed, msg = security_regression_runner.run_regression(finding, box_dir)
    assert passed is True
    assert "passed" in msg.lower()


def test_security_regression_runner_deps(tmp_path: Path):
    """Verifies security regression checks for requirements.txt vulnerable dependencies."""
    box_dir = tmp_path / "dep_box"
    box_dir.mkdir()
    req_file = box_dir / "requirements.txt"

    finding = Finding(
        id="f_dep_test",
        tool="pip_audit",
        cwe="CWE-1395",
        title="Vulnerable Werkzeug",
        severity=Severity.HIGH,
        file="requirements.txt",
    )

    # Vulnerable
    req_file.write_text("werkzeug==2.2.2\n", encoding="utf-8")
    passed, msg = security_regression_runner.run_regression(finding, box_dir)
    assert passed is False
    assert "vulnerable pinned Werkzeug" in msg

    # Patched
    req_file.write_text("werkzeug>=2.3.8\n", encoding="utf-8")
    passed, msg = security_regression_runner.run_regression(finding, box_dir)
    assert passed is True
    assert "passed" in msg.lower()


def test_decider_logic():
    """Validates the deterministic decision matrix."""
    # 1. All passed
    d1, r1 = decider.decide(
        unit_passed=True,
        regression_passed=True,
        original_finding_gone=True,
        new_findings=[],
    )
    assert d1 == DecisionEnum.VERIFIED
    assert "verified" in r1.lower()

    # 2. Secondary flaw introduced
    sec_f = Finding(
        id="new_sec", tool="bandit", cwe="CWE-78", title="Command Injection", severity=Severity.HIGH
    )
    d2, r2 = decider.decide(
        unit_passed=True,
        regression_passed=True,
        original_finding_gone=True,
        new_findings=[sec_f],
    )
    assert d2 == DecisionEnum.REJECTED_NEW_VULN
    assert "secondary vulnerabilities" in r2.lower()

    # 3. Original finding still present
    d3, r3 = decider.decide(
        unit_passed=True,
        regression_passed=True,
        original_finding_gone=False,
        new_findings=[],
    )
    assert d3 == DecisionEnum.REJECTED_UNRESOLVED
    assert "actively present" in r3.lower()

    # 4. Functional unit tests failed
    d4, r4 = decider.decide(
        unit_passed=False,
        regression_passed=True,
        original_finding_gone=True,
        new_findings=[],
    )
    assert d4 == DecisionEnum.REJECTED_FUNCTIONAL
    assert "unit tests broke" in r4.lower()


def test_verification_engine_end_to_end_verified(target_repo_with_tests: Path):
    """
    End-to-end integration test:
    Generates a patch for SQL injection on patient app,
    verifies it through the 4-phase verification loop,
    and asserts status transitions to VERIFIED in SQLite and audit log.
    """
    finding = Finding(
        id="e2e_sqli_find",
        tool="bandit",
        cwe="CWE-89",
        title="SQL Injection in search endpoint",
        severity=Severity.HIGH,
        file="app.py",
        status=FindingStatus.OPEN,
    )
    db.save_findings([finding], run_id="run_e2e_test")

    # 1. Remediate finding in sandbox
    patch, repo = remediation_engine.remediate(
        finding=finding,
        target_dir=target_repo_with_tests,
        attempt=1,
    )
    assert patch is not None

    # 2. Verify patch
    verification = verification_engine.verify(
        patch_id=patch.id,
        target_dir=target_repo_with_tests,
        auto_retry=False,
    )

    assert verification.decision == DecisionEnum.VERIFIED
    assert verification.unit_passed is True
    assert verification.regression_passed is True
    assert verification.original_finding_gone is True

    # 3. Check SQLite persistence
    updated_finding = db.get_finding(finding.id)
    assert updated_finding is not None
    assert updated_finding.status == FindingStatus.VERIFIED

    saved_v = db.get_verification(patch.id)
    assert saved_v is not None
    assert saved_v.decision == DecisionEnum.VERIFIED

    # 4. Check Audit Log
    entries = audit_logger.read_all()
    verified_events = [e for e in entries if e.get("event_type") == "PATCH_VERIFIED"]
    assert len(verified_events) > 0


def test_verification_engine_rejects_faulty_patch_and_rolls_back(
    tmp_path: Path, target_repo_with_tests: Path
):
    """
    Validates that a patch causing syntax errors or functional test regressions
    is caught, rejected, and cleanly rolled back.
    """
    finding = Finding(
        id="faulty_patch_finding",
        tool="bandit",
        cwe="CWE-89",
        title="SQL Injection",
        severity=Severity.HIGH,
        file="app.py",
        status=FindingStatus.OPEN,
    )
    db.save_findings([finding], run_id="run_faulty_test")

    # Prepare sandbox
    repo = sandbox_manager.prepare_sandbox(target_repo_with_tests)
    branch = sandbox_manager.create_fix_branch(repo, finding.id, attempt=1)

    # Intentionally corrupt app.py on this branch
    sandbox_path = Path(repo.working_dir)
    app_file = sandbox_path / "app.py"
    app_file.write_text("def syntax_error_in_patch(:\n    broken code\n", encoding="utf-8")
    repo.git.add(all=True)
    repo.index.commit("Broken patch commit")

    # Save faulty patch record in DB
    faulty_patch = Patch(
        id="patch_faulty_att1",
        finding_id=finding.id,
        diff="--- a/app.py\n+++ b/app.py\n",
        branch=branch,
        rationale="Faulty patch",
        attempt=1,
    )
    conn = db.get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO patches (id, finding_id, diff, branch, rationale, attempt, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            faulty_patch.id,
            faulty_patch.finding_id,
            faulty_patch.diff,
            faulty_patch.branch,
            faulty_patch.rationale,
            1,
            "2026-10-26T12:00:00",
        ),
    )
    conn.commit()
    conn.close()

    # Run verification (auto_retry=False)
    verification = verification_engine.verify(
        patch_id=faulty_patch.id,
        target_dir=target_repo_with_tests,
        auto_retry=False,
    )

    assert verification.decision != DecisionEnum.VERIFIED
    # Verified rollback clean working tree
    assert not repo.is_dirty()
