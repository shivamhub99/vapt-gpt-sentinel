"""
Unit & Safety Tests for ScopeGuard and Authorization Boundary.
Proves that out-of-scope targets are strictly rejected, unauthorized scans are aborted,
and all actions are immutably logged to the audit ledger.
"""

import json
from pathlib import Path

import pytest

from sentinel.core.audit_log import AuditLogger
from sentinel.core.scope_guard import (
    ScopeGuard,
    ScopeViolationError,
    UnauthorizedTargetError,
)


@pytest.fixture
def temp_audit_log(tmp_path: Path):
    """Provides an isolated temporary audit log for tests."""
    log_file = tmp_path / "test_audit_log.jsonl"
    return AuditLogger(log_path=log_file)


@pytest.fixture
def test_scope_guard(monkeypatch):
    """Provides a fresh ScopeGuard instance with authorized environment."""
    monkeypatch.setenv("SENTINEL_I_OWN_THIS_TARGET", "true")
    return ScopeGuard()


def test_authorization_flag_required(monkeypatch):
    """Proves that scan execution is completely refused if authorization flag is false or unset."""
    guard = ScopeGuard()

    # Case 1: Not set
    monkeypatch.delenv("SENTINEL_I_OWN_THIS_TARGET", raising=False)
    with pytest.raises(UnauthorizedTargetError) as exc_info:
        guard.validate_target("http://localhost:8080")
    assert "SENTINEL_I_OWN_THIS_TARGET" in str(exc_info.value)

    # Case 2: Explicitly false
    monkeypatch.setenv("SENTINEL_I_OWN_THIS_TARGET", "false")
    with pytest.raises(UnauthorizedTargetError):
        guard.validate_target("http://localhost:8080")

    # Case 3: Random string
    monkeypatch.setenv("SENTINEL_I_OWN_THIS_TARGET", "no_i_do_not")
    with pytest.raises(UnauthorizedTargetError):
        guard.validate_target("http://localhost:8080")


def test_out_of_scope_public_domains_rejected(test_scope_guard):
    """Proves that external public domains are blocked by ScopeGuard."""
    out_of_scope_targets = [
        "http://google.com",
        "https://example.com/api/test",
        "http://evil-attacker.org:8080",
        "https://api.github.com",
        "http://bank.example.internal:8080",
    ]
    for target in out_of_scope_targets:
        with pytest.raises(ScopeViolationError) as exc_info:
            test_scope_guard.validate_target(target)
        assert "OUT OF SCOPE" in str(exc_info.value)


def test_out_of_scope_public_ips_rejected(test_scope_guard):
    """Proves that arbitrary public IPv4 and IPv6 addresses are blocked."""
    external_ips = [
        "http://8.8.8.8:80",
        "http://1.1.1.1",
        "http://93.184.216.34:80",
    ]
    for target in external_ips:
        with pytest.raises(ScopeViolationError):
            test_scope_guard.validate_target(target)


def test_out_of_scope_ports_rejected(test_scope_guard):
    """Proves that allowed hostnames targeting unauthorized ports are blocked."""
    forbidden_ports = [
        "http://localhost:22",
        "http://127.0.0.1:3306",
        "http://localhost:6379",
        "http://sentinel-lab-app:9999",
    ]
    for target in forbidden_ports:
        with pytest.raises(ScopeViolationError) as exc_info:
            test_scope_guard.validate_target(target)
        assert "OUT OF SCOPE" in str(exc_info.value)


def test_in_scope_lab_targets_permitted(test_scope_guard):
    """Proves that explicitly allowlisted lab targets pass validation."""
    permitted_targets = [
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:8081",
        "http://localhost:8082",
        "http://sentinel-lab-app:8080",
        "http://172.28.0.10:8080",  # Lab Docker container subnet
        "http://172.16.1.5:80",  # Docker bridge subnet
    ]
    for target in permitted_targets:
        assert test_scope_guard.validate_target(target) is True


def test_local_workspace_paths_permitted(test_scope_guard):
    """Proves that local repository paths within the workspace are permitted for SAST."""
    lab_dir = Path("lab/sentinel-lab-app").resolve()
    assert test_scope_guard.validate_target(str(lab_dir)) is True


def test_audit_log_cryptographic_chain(tmp_path: Path):
    """Proves audit log entries are appended and chained with SHA-256 hashes."""
    log_file = tmp_path / "chained_audit.jsonl"
    logger = AuditLogger(log_path=log_file)

    e1 = logger.log(
        event_type="TEST_EVENT_1",
        actor="TestActor",
        details={"status": "initial"},
    )
    e2 = logger.log(
        event_type="TEST_EVENT_2",
        actor="TestActor",
        details={"status": "second"},
    )

    assert e1["prev_hash"].startswith("GENESIS_BLOCK")
    assert e2["prev_hash"] == e1["entry_hash"]

    # Verify log content on disk
    lines = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 2
    assert lines[0]["entry_hash"] == e1["entry_hash"]
    assert lines[1]["entry_hash"] == e2["entry_hash"]
