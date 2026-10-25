"""
Unit and Integration Tests for Finding Normalization, CWE/OWASP Mapping,
Deduplication, and SQLite Persistence.
"""

import json
from pathlib import Path

import pytest

from sentinel.core.database import Database
from sentinel.core.schemas import Finding, FindingStatus, Severity
from sentinel.normalize.cwe_map import get_owasp_category, normalize_cwe
from sentinel.normalize.dedupe import are_findings_duplicate, deduplicate_findings, merge_findings
from sentinel.normalize.normalizer import Normalizer


@pytest.fixture
def temp_db(tmp_path: Path):
    """Provides a fresh isolated SQLite database instance."""
    db_file = tmp_path / "test_sentinel.db"
    return Database(db_path=db_file)


def test_cwe_mapping_accuracy():
    """Validates translation of heterogeneous tool rules to canonical CWEs."""
    # Bandit rule IDs
    assert normalize_cwe("bandit", "B608") == "CWE-89"
    assert normalize_cwe("bandit", "B105") == "CWE-798"
    assert normalize_cwe("bandit", "B104") == "CWE-200"

    # ZAP plugin IDs
    assert normalize_cwe("zap", "40018") == "CWE-89"
    assert normalize_cwe("zap", "40012") == "CWE-79"
    assert normalize_cwe("zap", "10038") == "CWE-693"
    assert normalize_cwe("zap", "10020") == "CWE-1021"

    # Headers & CORS
    assert normalize_cwe("headers", "missing_header") == "CWE-693"
    assert normalize_cwe("headers", "cors_wildcard") == "CWE-942"
    assert normalize_cwe("headers", "insecure_cookie") == "CWE-614"

    # Semgrep rule keywords
    assert normalize_cwe("semgrep", "python.flask.security.sqli") == "CWE-89"
    assert normalize_cwe("semgrep", "rules.owasp.xss_reflection") == "CWE-79"

    # Dependencies
    assert normalize_cwe("pip_audit", "CVE-2023-25577") == "CWE-1395"


def test_owasp_category_mapping():
    """Validates mapping from canonical CWE to OWASP Top 10 (2021)."""
    assert get_owasp_category("CWE-89") == "A03:2021-Injection"
    assert get_owasp_category("CWE-79") == "A03:2021-Injection"
    assert get_owasp_category("CWE-798") == "A07:2021-Identification and Authentication Failures"
    assert get_owasp_category("CWE-1395") == "A06:2021-Vulnerable and Outdated Components"
    assert get_owasp_category("CWE-639") == "A01:2021-Broken Access Control"
    assert get_owasp_category("CWE-693") == "A05:2021-Security Misconfiguration"


def test_deduplication_source_code_findings():
    """Validates that findings from multiple tools at the same code location are merged."""
    f1 = Finding(
        id="f1",
        tool="bandit",
        cwe="CWE-89",
        title="SQL Injection in search query",
        severity=Severity.HIGH,
        file="app.py",
        line=150,
        evidence="cursor.execute(f'SELECT ...')",
    )
    f2 = Finding(
        id="f2",
        tool="semgrep",
        cwe="CWE-89",
        title="Unescaped formatted SQL string",
        severity=Severity.CRITICAL,
        file="app.py",
        line=152,
        evidence="cursor.execute(raw_sql)",
    )

    assert are_findings_duplicate(f1, f2) is True

    merged = merge_findings(f1, f2)
    assert "bandit" in merged.tool
    assert "semgrep" in merged.tool
    assert merged.severity == Severity.CRITICAL  # Takes highest severity
    assert merged.cwe == "CWE-89"


def test_deduplication_web_endpoint_findings():
    """Validates that DAST findings for the same endpoint and check are merged."""
    f1 = Finding(
        id="f1",
        tool="headers",
        cwe="CWE-693",
        title="Missing Content Security Policy",
        severity=Severity.MEDIUM,
        endpoint="http://localhost:8080/api/search",
        evidence="CSP absent",
    )
    f2 = Finding(
        id="f2",
        tool="zap",
        cwe="CWE-693",
        title="CSP Header Not Set",
        severity=Severity.HIGH,
        endpoint="http://localhost:8080/api/search",
        evidence="No CSP header returned",
    )

    assert are_findings_duplicate(f1, f2) is True
    merged = merge_findings(f1, f2)
    assert merged.severity == Severity.HIGH
    assert "headers" in merged.tool and "zap" in merged.tool


def test_deduplication_distinct_findings_kept_separate():
    """Validates that distinct vulnerabilities are not incorrectly merged."""
    f_sqli = Finding(
        id="f1",
        tool="bandit",
        cwe="CWE-89",
        title="SQLi",
        severity=Severity.HIGH,
        file="app.py",
        line=150,
    )
    f_xss = Finding(
        id="f2",
        tool="zap",
        cwe="CWE-79",
        title="XSS",
        severity=Severity.HIGH,
        file="app.py",
        line=180,
    )

    deduped = deduplicate_findings([f_sqli, f_xss])
    assert len(deduped) == 2


def test_sqlite_persistence_roundtrip(temp_db: Database):
    """Verifies storing, retrieving, and updating findings in SQLite."""
    run_id = "test_run_persist"
    finding = Finding(
        id="finding_cwe_89_test01",
        tool="bandit,semgrep",
        cwe="CWE-89",
        owasp="A03:2021-Injection",
        title="Planted SQL Injection",
        severity=Severity.CRITICAL,
        cvss=8.8,
        epss=0.45,
        file="lab/sentinel-lab-app/app.py",
        line=150,
        endpoint="http://localhost:8080/api/search",
        param="q",
        evidence="cursor.execute(f'SELECT...')",
        status=FindingStatus.OPEN,
    )

    temp_db.save_run(run_id=run_id, target="http://localhost:8080", findings_count=1)
    temp_db.save_findings([finding], run_id=run_id)

    # Retrieve by run
    results = temp_db.get_findings_by_run(run_id)
    assert len(results) == 1
    loaded = results[0]
    assert loaded.id == "finding_cwe_89_test01"
    assert loaded.cwe == "CWE-89"
    assert loaded.severity == Severity.CRITICAL
    assert loaded.cvss == 8.8

    # Update status
    temp_db.update_finding_status(loaded.id, FindingStatus.VERIFIED)
    refreshed = temp_db.get_finding(loaded.id)
    assert refreshed.status == FindingStatus.VERIFIED


def test_normalization_yields_all_six_planted_findings(tmp_path: Path):
    """
    Acceptance Test: Normalizing a complete set of scanner fixture outputs for sentinel-lab-app
    yields at least the six planted vulnerability categories:
    1. SQLi (CWE-89)
    2. Reflected XSS (CWE-79)
    3. Hardcoded Secret (CWE-798)
    4. Vulnerable Dependencies (CWE-1395)
    5. Insecure Direct Object Reference (CWE-639)
    6. Missing Security Headers / CORS (CWE-693 / CWE-942)
    """
    run_id = "acceptance_lab_run"
    raw_dir = tmp_path / run_id / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    # 1. Bandit fixture (SQLi & Secret)
    bandit_data = {
        "success": True,
        "tool": "bandit",
        "data": {
            "results": [
                {
                    "test_id": "B608",
                    "issue_text": "Possible SQL injection vector via string formatting",
                    "issue_severity": "HIGH",
                    "issue_cwe": {"id": 89},
                    "filename": "lab/sentinel-lab-app/app.py",
                    "line_number": 150,
                    "code": "cursor.execute(f'SELECT ...')",
                },
                {
                    "test_id": "B105",
                    "issue_text": "Hardcoded password/token key string",
                    "issue_severity": "MEDIUM",
                    "issue_cwe": {"id": 798},
                    "filename": "lab/sentinel-lab-app/app.py",
                    "line_number": 25,
                    "code": "API_SECRET_KEY = 'SENTINEL-SECRET-KEY-9988-PROD-DO-NOT-LEAK'",
                },
            ]
        },
    }
    (raw_dir / "bandit.json").write_text(json.dumps(bandit_data), encoding="utf-8")

    # 2. Gitleaks fixture (Secret)
    gitleaks_data = {
        "success": True,
        "tool": "gitleaks",
        "data": {
            "findings": [
                {
                    "Description": "Planted Lab API Secret Key",
                    "File": "lab/sentinel-lab-app/app.py",
                    "StartLine": 25,
                    "Match": "SENTINEL-SECRET-KEY-9988-PROD-DO-NOT-LEAK",
                    "RuleID": "sentinel-secret-rule",
                    "CWE": "CWE-798",
                }
            ]
        },
    }
    (raw_dir / "gitleaks.json").write_text(json.dumps(gitleaks_data), encoding="utf-8")

    # 3. ZAP fixture (Reflected XSS & SQLi & IDOR alert)
    zap_data = {
        "success": True,
        "tool": "zap",
        "data": {
            "site": [
                {
                    "@name": "http://localhost:8080",
                    "alerts": [
                        {
                            "pluginId": "40012",
                            "alert": "Cross Site Scripting (Reflected)",
                            "riskcode": "3",
                            "cweid": "79",
                            "uri": "http://localhost:8080/api/greet",
                            "param": "name",
                            "evidence": "Unescaped reflection in HTML response",
                        },
                        {
                            "pluginId": "40018",
                            "alert": "SQL Injection in search query",
                            "riskcode": "3",
                            "cweid": "89",
                            "uri": "http://localhost:8080/api/search",
                            "param": "q",
                            "evidence": "Unescaped string concatenation",
                        },
                        {
                            "pluginId": "40020",
                            "alert": "Insecure Direct Object Reference (IDOR) on /api/orders",
                            "riskcode": "3",
                            "cweid": "639",
                            "uri": "http://localhost:8080/api/orders/1",
                            "evidence": "Missing access control check on object ID",
                        },
                    ],
                }
            ]
        },
    }
    (raw_dir / "zap.json").write_text(json.dumps(zap_data), encoding="utf-8")

    # 4. pip-audit fixture (Dependencies)
    pip_audit_data = {
        "success": True,
        "tool": "pip_audit",
        "data": {
            "dependencies": [
                {
                    "name": "Werkzeug",
                    "version": "2.2.2",
                    "vulns": [
                        {
                            "id": "CVE-2023-25577",
                            "fix_versions": ["2.2.3"],
                            "description": "Denial of service in multipart form data parser",
                        }
                    ],
                }
            ]
        },
    }
    (raw_dir / "pip_audit.json").write_text(json.dumps(pip_audit_data), encoding="utf-8")

    # 5. Headers fixture (Missing security headers & CORS)
    headers_data = {
        "success": True,
        "tool": "headers",
        "data": {
            "findings": [
                {
                    "check": "missing_header",
                    "header": "Content-Security-Policy",
                    "title": "Missing Content Security Policy (CSP)",
                    "cwe": "CWE-693",
                    "severity": "HIGH",
                    "evidence": "Header 'Content-Security-Policy' was absent",
                    "endpoint": "http://localhost:8080/",
                },
                {
                    "check": "cors_wildcard",
                    "title": "Overly Permissive CORS Policy",
                    "cwe": "CWE-942",
                    "severity": "MEDIUM",
                    "evidence": "Access-Control-Allow-Origin: *",
                    "endpoint": "http://localhost:8080/",
                },
            ]
        },
    }
    (raw_dir / "headers.json").write_text(json.dumps(headers_data), encoding="utf-8")

    # Run Normalizer on fixture directory
    norm = Normalizer(runs_dir=tmp_path)
    findings = norm.normalize_run(run_id=run_id, persist=False)

    cwes_found = {f.cwe for f in findings}

    # Verify at least the 6 planted issues are detected and normalized:
    assert "CWE-89" in cwes_found  # 1. SQL Injection
    assert "CWE-79" in cwes_found  # 2. Reflected XSS
    assert "CWE-798" in cwes_found  # 3. Hardcoded Secret
    assert "CWE-1395" in cwes_found  # 4. Vulnerable Dependencies
    assert "CWE-639" in cwes_found  # 5. IDOR Access Control
    assert "CWE-693" in cwes_found or "CWE-942" in cwes_found  # 6. Security Headers / CORS

    # Verify deduplication occurred:
    # Secret was reported by both Bandit and Gitleaks on app.py:25 -> should be merged into 1 finding!
    secret_findings = [f for f in findings if f.cwe == "CWE-798"]
    assert len(secret_findings) == 1
    assert "bandit" in secret_findings[0].tool and "gitleaks" in secret_findings[0].tool
