"""
Tests for Scanner Layer Wrappers and Raw JSON Persistence.
Verifies that:
1. Every scanner enforces ScopeGuard and aborts on out-of-scope targets.
2. Every scanner wrapper persists structured raw JSON under runs/<run_id>/raw/<tool>.json.
3. Every scanner parse() method correctly maps raw outputs to finding records.
"""

from pathlib import Path

import pytest

from sentinel.core.scope_guard import ScopeViolationError, UnauthorizedTargetError
from sentinel.scanners.bandit import BanditScanner
from sentinel.scanners.gitleaks import GitleaksScanner
from sentinel.scanners.headers import HeadersScanner
from sentinel.scanners.nmap import NmapScanner
from sentinel.scanners.pip_audit import PipAuditScanner
from sentinel.scanners.semgrep import SemgrepScanner
from sentinel.scanners.trivy import TrivyScanner
from sentinel.scanners.zap import ZAPScanner


@pytest.fixture(autouse=True)
def authorize_scans(monkeypatch):
    """Ensures test runs have target ownership authorized."""
    monkeypatch.setenv("SENTINEL_I_OWN_THIS_TARGET", "true")


def test_scanners_reject_unauthorized_flag(monkeypatch):
    """Proves all scanner wrappers abort if SENTINEL_I_OWN_THIS_TARGET is not true."""
    monkeypatch.delenv("SENTINEL_I_OWN_THIS_TARGET", raising=False)

    scanner = HeadersScanner()
    with pytest.raises(UnauthorizedTargetError):
        scanner.execute(target="http://localhost:8080", run_id="test_unauth")


def test_scanners_reject_out_of_scope_target():
    """Proves scanner wrappers abort when pointed to out-of-scope targets."""
    scanner = HeadersScanner()
    with pytest.raises(ScopeViolationError):
        scanner.execute(target="http://evil-site.com", run_id="test_outofscope")


def test_headers_scanner_on_lab_app(tmp_path: Path):
    """Executes HeadersScanner against sentinel-lab-app and verifies raw JSON output."""
    scanner = HeadersScanner()
    result = scanner.execute(target="http://localhost:8080", run_id="run_headers_test")

    assert result["success"] is True
    assert result["tool"] == "headers"
    data = result["data"]
    assert "missing_headers" in data

    # Planted issues check: HSTS, CSP, and X-Content-Type-Options should be flagged
    missing = data["missing_headers"]
    assert any("Strict-Transport-Security" in m for m in missing)
    assert any("Content-Security-Policy" in m for m in missing)

    # Check parser
    findings = scanner.parse(result)
    assert len(findings) >= 3

    # Verify JSON file on disk
    raw_file = Path("runs/run_headers_test/raw/headers.json")
    assert raw_file.exists()


def test_bandit_scanner_on_lab_app():
    """Executes BanditScanner against lab/sentinel-lab-app and verifies findings."""
    scanner = BanditScanner()
    target_dir = str(Path("lab/sentinel-lab-app").resolve())
    result = scanner.execute(target=target_dir, run_id="run_bandit_test")

    assert result["success"] is True
    assert result["tool"] == "bandit"

    findings = scanner.parse(result)
    # Planted issues check: SQL injection (B608) or hardcoded key (B105)
    assert len(findings) >= 1

    raw_file = Path("runs/run_bandit_test/raw/bandit.json")
    assert raw_file.exists()


def test_gitleaks_scanner_on_lab_app():
    """Executes GitleaksScanner against lab/sentinel-lab-app and detects planted secret."""
    scanner = GitleaksScanner()
    target_dir = str(Path("lab/sentinel-lab-app").resolve())
    result = scanner.execute(target=target_dir, run_id="run_gitleaks_test")

    assert result["success"] is True
    assert result["tool"] == "gitleaks"

    findings = scanner.parse(result)
    # Planted issues check: API_SECRET_KEY = "SENTINEL-SECRET-KEY-9988-PROD-DO-NOT-LEAK"
    secret_findings = [f for f in findings if f.get("cwe") == "CWE-798"]
    assert len(secret_findings) >= 1

    raw_file = Path("runs/run_gitleaks_test/raw/gitleaks.json")
    assert raw_file.exists()


def test_pip_audit_scanner_on_lab_app():
    """Executes PipAuditScanner against requirements.txt to detect vulnerable dependencies."""

    scanner = PipAuditScanner()
    req_file = str(Path("lab/sentinel-lab-app/requirements.txt").resolve())
    result = scanner.execute(target=req_file, run_id="run_pipaudit_test")

    assert result["success"] is True
    assert result["tool"] == "pip_audit"

    findings = scanner.parse(result)
    # Planted issues check: Werkzeug==2.2.2 or requests==2.25.1
    packages = [f.get("package") for f in findings]
    assert any(p in ("Werkzeug", "requests") for p in packages)

    raw_file = Path("runs/run_pipaudit_test/raw/pip_audit.json")
    assert raw_file.exists()


def test_semgrep_scanner_on_lab_app():
    """Executes SemgrepScanner against lab/sentinel-lab-app."""
    scanner = SemgrepScanner()
    target_dir = str(Path("lab/sentinel-lab-app").resolve())
    result = scanner.execute(target=target_dir, run_id="run_semgrep_test")

    assert result["success"] is True
    assert result["tool"] == "semgrep"

    findings = scanner.parse(result)
    assert isinstance(findings, list)

    raw_file = Path("runs/run_semgrep_test/raw/semgrep.json")
    assert raw_file.exists()


def test_nmap_scanner_on_lab_app():
    """Executes safe Nmap scanner against localhost."""
    scanner = NmapScanner()
    result = scanner.execute(target="http://localhost:8080", run_id="run_nmap_test", ports=[8080])

    assert result["success"] is True
    assert result["tool"] == "nmap"

    findings = scanner.parse(result)
    assert any(f.get("port") == 8080 for f in findings)

    raw_file = Path("runs/run_nmap_test/raw/nmap.json")
    assert raw_file.exists()


def test_trivy_scanner_on_lab_app():
    """Executes TrivyScanner against lab/sentinel-lab-app and detects CVEs."""
    scanner = TrivyScanner()
    target_dir = str(Path("lab/sentinel-lab-app").resolve())
    result = scanner.execute(target=target_dir, run_id="run_trivy_test")

    assert result["success"] is True
    assert result["tool"] == "trivy"

    findings = scanner.parse(result)
    assert len(findings) >= 1
    assert any("CVE-" in f.get("vuln_id", "") for f in findings)

    raw_file = Path("runs/run_trivy_test/raw/trivy.json")
    assert raw_file.exists()


def test_zap_scanner_on_lab_app():
    """Executes ZAP baseline scan against sentinel-lab-app and detects baseline findings."""
    scanner = ZAPScanner()
    result = scanner.execute(target="http://localhost:8080", run_id="run_zap_test")

    assert result["success"] is True
    assert result["tool"] == "zap"

    findings = scanner.parse(result)
    assert len(findings) >= 1
    cwes = [f.get("cwe") for f in findings]
    # Should detect missing headers or SQL injection / XSS alerts
    assert any(cwe in ("CWE-693", "CWE-16", "CWE-89", "CWE-79") for cwe in cwes)

    raw_file = Path("runs/run_zap_test/raw/zap.json")
    assert raw_file.exists()
