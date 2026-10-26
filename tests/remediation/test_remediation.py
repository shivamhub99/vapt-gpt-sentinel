"""
Unit and Integration Tests for Phase 4: Remediation Engine and Sandboxed Patch Application.
Validates:
1. Deterministic template fixes for SQLi, XSS, Hardcoded Secrets, Vulnerable Deps, and Headers.
2. Isolated Git sandbox cloning and dedicated branch creation.
3. Clean rollback on patch application conflict.
4. Hard Safety Rule 4: Primary target worktree is never modified.
5. Hard Safety Rule 5: Risky categories (CWE-639, CWE-287, CWE-284) gated to NEEDS_HUMAN.
6. LLM fallback when deterministic templates do not match.
"""

from pathlib import Path

import git
import pytest

from sentinel.core.audit_log import audit_logger
from sentinel.core.database import db
from sentinel.core.schemas import Finding, FindingStatus, Severity
from sentinel.llm.mock import MockProvider
from sentinel.remediation.engine import RemediationEngine, RemediationGatedError
from sentinel.remediation.fixers.deps import DependencyFixer
from sentinel.remediation.fixers.headers import HeadersFixer
from sentinel.remediation.fixers.secrets import SecretsFixer
from sentinel.remediation.fixers.sqli import SQLInjectionFixer
from sentinel.remediation.fixers.xss import XSSFixer
from sentinel.remediation.patch_apply import PatchApplicationError, SandboxManager


@pytest.fixture
def test_target_repo(tmp_path: Path) -> Path:
    """Creates a local dummy target Git repository representing a patient app."""
    target_dir = tmp_path / "target_patient_app"
    target_dir.mkdir(parents=True, exist_ok=True)

    app_py = target_dir / "app.py"
    app_py.write_text(
        "from flask import Flask, request, jsonify\n"
        "app = Flask(__name__)\n\n"
        'API_SECRET_KEY = "vuln_insecure_token_12345"\n\n'
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

    # Initialize git repo and commit
    repo = git.Repo.init(target_dir)
    repo.git.config("user.name", "Sentinel Test")
    repo.git.config("user.email", "test@sentinel.local")
    repo.git.add(all=True)
    repo.index.commit("Initial target repository commit")

    return target_dir


def test_sqli_fixer_template():
    """Validates SQL injection parameterized query transformation."""
    fixer = SQLInjectionFixer()
    finding = Finding(
        id="find_sqli_01",
        tool="bandit",
        cwe="CWE-89",
        title="SQL Injection in search query",
        severity=Severity.HIGH,
        file="app.py",
    )
    vuln_code = (
        "def search_products(query):\n"
        "    raw_sql = f\"SELECT id, name, description, price FROM products WHERE name LIKE '%{query}%'\"\n"
        "    cursor.execute(raw_sql)\n"
        "    return cursor.fetchall()\n"
    )
    res = fixer.apply_template(finding, vuln_code, Path("app.py"))
    assert res is not None
    mod_code, rationale = res
    assert 'query_param = f"%{query}%"' in mod_code
    assert (
        'cursor.execute("SELECT id, name, description, price FROM products WHERE name LIKE ?", (query_param,))'
        in mod_code
    )
    assert "parameterized" in rationale.lower()
    compile(mod_code, "test.py", "exec")


def test_xss_fixer_template():
    """Validates reflected XSS HTML escaping transformation."""
    fixer = XSSFixer()
    finding = Finding(
        id="find_xss_01",
        tool="semgrep",
        cwe="CWE-79",
        title="Reflected XSS in greeting",
        severity=Severity.HIGH,
        file="app.py",
    )
    vuln_code = (
        "from flask import Flask, Response, request\n"
        "app = Flask(__name__)\n\n"
        '@app.route("/api/greet")\n'
        "def greet():\n"
        '    name = request.args.get("name", "Guest")\n'
        '    html_content = f"<html><body>Welcome, {name}!</body></html>"\n'
        '    return Response(html_content, mimetype="text/html")\n'
    )
    res = fixer.apply_template(finding, vuln_code, Path("app.py"))
    assert res is not None
    mod_code, rationale = res
    assert "from markupsafe import escape" in mod_code
    assert "safe_name = escape(name)" in mod_code
    assert "{safe_name}" in mod_code
    assert "markupsafe.escape()" in rationale
    compile(mod_code, "test.py", "exec")


def test_secrets_fixer_template(tmp_path: Path):
    """Validates hardcoded secret migration to os.environ and .env.example generation."""
    fixer = SecretsFixer()
    finding = Finding(
        id="find_sec_01",
        tool="gitleaks",
        cwe="CWE-798",
        title="Hardcoded API Secret Key",
        severity=Severity.CRITICAL,
        file="app.py",
    )
    test_dir = tmp_path / "secrets_test"
    test_dir.mkdir()
    app_file = test_dir / "app.py"
    vuln_code = 'import os\nAPI_SECRET_KEY = "hardcoded_secret_token_abcdef"\n'
    app_file.write_text(vuln_code, encoding="utf-8")

    res = fixer.apply_template(finding, vuln_code, app_file)
    assert res is not None
    mod_code, rationale = res
    assert (
        'API_SECRET_KEY = os.environ.get("API_SECRET_KEY", "hardcoded_secret_token_abcdef")'
        in mod_code
    )

    env_ex = test_dir / ".env.example"
    assert env_ex.exists()
    assert "API_SECRET_KEY=your_api_secret_key_here" in env_ex.read_text(encoding="utf-8")
    assert "os.environ.get()" in rationale
    compile(mod_code, "test.py", "exec")


def test_deps_fixer_template(tmp_path: Path):
    """Validates pinned vulnerable dependency upgrading in requirements.txt."""
    fixer = DependencyFixer()
    finding = Finding(
        id="find_dep_01",
        tool="pip_audit",
        cwe="CWE-1395",
        title="Vulnerable Werkzeug Dependency",
        severity=Severity.HIGH,
        file="requirements.txt",
        raw_tool_data={"package": "werkzeug"},
    )
    test_dir = tmp_path / "dep_test"
    test_dir.mkdir()
    req_file = test_dir / "requirements.txt"
    orig_req = "flask==2.2.5\nwerkzeug==2.2.2\nrequests==2.25.1\n"
    req_file.write_text(orig_req, encoding="utf-8")

    res = fixer.apply_template(finding, orig_req, req_file)
    assert res is not None
    mod_code, rationale = res
    assert "werkzeug>=2.3.8" in mod_code
    assert "requirements.txt" in rationale


def test_headers_fixer_template():
    """Validates HTTP security headers injection and cookie hardening."""
    fixer = HeadersFixer()
    finding = Finding(
        id="find_hdr_01",
        tool="headers",
        cwe="CWE-693",
        title="Missing Content Security Policy and Permissive CORS",
        severity=Severity.MEDIUM,
        file="app.py",
    )
    code = (
        "@app.after_request\n"
        "def apply_headers(response):\n"
        '    response.headers["Access-Control-Allow-Origin"] = "*"\n'
        "    return response\n\n"
        "def do_login(resp):\n"
        '    resp.set_cookie("session_id", "demo_sess_1", httponly=False, secure=False)\n'
        "    return resp\n"
    )
    res = fixer.apply_template(finding, code, Path("app.py"))
    assert res is not None
    mod_code, rationale = res
    assert 'response.headers["Content-Security-Policy"] = "default-src \'self\'"' in mod_code
    assert 'response.headers["Strict-Transport-Security"]' in mod_code
    assert 'httponly=True, secure=True, samesite="Lax"' in mod_code
    compile(mod_code, "test.py", "exec")


def test_sandbox_isolated_branch_and_safety_boundary(tmp_path: Path, test_target_repo: Path):
    """
    Hard Safety Rule 4:
    Verifies that patch application executes strictly on an isolated sandbox branch,
    and that the original primary target repository worktree is COMPLETELY untouched.
    """
    sandbox_root = tmp_path / "isolated_sandboxes"
    manager = SandboxManager(sandbox_root=sandbox_root)

    orig_app_py = test_target_repo / "app.py"
    orig_content = orig_app_py.read_text(encoding="utf-8")

    # 1. Prepare sandbox
    sandbox_repo = manager.prepare_sandbox(test_target_repo)
    assert Path(sandbox_repo.working_dir).resolve() != test_target_repo.resolve()

    # 2. Create dedicated branch
    branch_name = manager.create_fix_branch(sandbox_repo, finding_id="finding_123", attempt=1)
    assert branch_name == "sentinel/fix-finding-123-att1"
    assert sandbox_repo.active_branch.name == branch_name

    # 3. Apply a unified diff to sandbox
    mod_content = orig_content.replace(
        'API_SECRET_KEY = "vuln_insecure_token_12345"',
        'API_SECRET_KEY = os.environ.get("API_SECRET_KEY", "vuln_insecure_token_12345")',
    )
    diff_text = SecretsFixer().generate_unified_diff(orig_content, mod_content, "app.py")
    success = manager.apply_diff(
        repo=sandbox_repo,
        diff_text=diff_text,
        finding_id="finding_123",
        rationale="Secured API key via environment variable",
    )
    assert success is True

    # 4. Sandbox file should be updated on this branch
    sandbox_app_py = Path(sandbox_repo.working_dir) / "app.py"
    assert 'os.environ.get("API_SECRET_KEY"' in sandbox_app_py.read_text(encoding="utf-8")

    # 5. HARD SAFETY RULE: Primary target worktree is 100% UNTOUCHED
    assert orig_app_py.read_text(encoding="utf-8") == orig_content
    # Target git repo has no new branches
    target_repo_obj = git.Repo(test_target_repo)
    assert branch_name not in [h.name for h in target_repo_obj.heads]


def test_sandbox_rollback_on_conflict(tmp_path: Path, test_target_repo: Path):
    """Verifies that patch conflict triggers clean rollback without leaving dirty git state."""
    sandbox_root = tmp_path / "sandboxes_conflict"
    manager = SandboxManager(sandbox_root=sandbox_root)
    sandbox_repo = manager.prepare_sandbox(test_target_repo)
    manager.create_fix_branch(sandbox_repo, finding_id="finding_conflict", attempt=1)

    # Invalid diff targeting non-existent code
    conflicting_diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -10,3 +10,3 @@\n"
        "-NON_EXISTENT_CODE_LINE_12345\n"
        "+REPLACED_CODE\n"
    )

    with pytest.raises(PatchApplicationError):
        manager.apply_diff(
            repo=sandbox_repo,
            diff_text=conflicting_diff,
            finding_id="finding_conflict",
            rationale="Conflict test",
        )

    # Sandbox working tree should be clean after rollback
    assert not sandbox_repo.is_dirty()


def test_remediation_engine_gated_risky_categories(tmp_path: Path, test_target_repo: Path):
    """
    Hard Safety Rule 5:
    Risky categories (CWE-639 IDOR, CWE-287 Auth, CWE-284 Access Control)
    MUST be gated, flagged as NEEDS_HUMAN, and never auto-remediated blindly.
    """
    engine = RemediationEngine()
    gated_finding = Finding(
        id="idor_order_access",
        tool="semgrep",
        cwe="CWE-639",
        title="IDOR Access Control Missing on Orders Endpoint",
        severity=Severity.HIGH,
        file="app.py",
        status=FindingStatus.OPEN,
    )
    db.save_findings([gated_finding], run_id="run_safety_test")

    with pytest.raises(RemediationGatedError) as exc_info:
        engine.remediate(finding=gated_finding, target_dir=test_target_repo, attempt=1)

    assert "authorization required" in str(exc_info.value).lower()

    # Verify status in database was updated to NEEDS_HUMAN
    saved = db.get_finding("idor_order_access")
    assert saved is not None
    assert saved.status == FindingStatus.NEEDS_HUMAN

    # Verify audit log contains REMEDIATION_GATED
    entries = audit_logger.read_all()
    gated_entries = [e for e in entries if e.get("event_type") == "REMEDIATION_GATED"]
    assert len(gated_entries) > 0
    assert gated_entries[-1]["details"]["finding_id"] == "idor_order_access"


def test_base_fixer_llm_fallback(tmp_path: Path):
    """Verifies that BaseFixer falls back to LLMProvider when regex template does not match."""
    mock_llm = MockProvider()
    fixer = SQLInjectionFixer(llm_provider=mock_llm)

    unusual_code = (
        "def custom_exec(conn, user_val):\n"
        '    stmt = "SELECT * FROM secrets WHERE id = " + user_val\n'
        "    return conn.execute(stmt)\n"
    )
    sandbox_dir = tmp_path / "llm_fallback_box"
    sandbox_dir.mkdir()
    app_file = sandbox_dir / "app.py"
    app_file.write_text(unusual_code, encoding="utf-8")

    finding = Finding(
        id="sqli_unusual",
        tool="bandit",
        cwe="CWE-89",
        title="SQL injection via string concatenation",
        severity=Severity.HIGH,
        file="app.py",
    )

    patch = fixer.fix(finding=finding, sandbox_dir=sandbox_dir, attempt=1)
    assert patch.generated_by == "llm"
    assert "query_param" in patch.diff
    assert "parameterized query binding" in patch.rationale
