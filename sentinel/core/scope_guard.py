"""
ScopeGuard: Hard safety boundary for VAPT-GPT Sentinel.
Enforces non-negotiable scope allowlisting from config/scope.yaml and ownership authorization.
"""

import ipaddress
import os
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

import yaml

from sentinel.core.audit_log import audit_logger
from sentinel.core.settings import settings


class ScopeViolationError(PermissionError):
    """Raised when a target is outside the defined scope allowlist."""


class UnauthorizedTargetError(PermissionError):
    """Raised when target ownership authorization is missing."""


class ScopeGuard:
    """
    Validates targets against authorization flags and scope allowlists.
    Every scanner wrapper MUST call ScopeGuard before executing any scan or network request.
    """

    def __init__(self, scope_path: Optional[Path] = None):
        self.scope_path = scope_path or settings.scope_path
        self._load_scope()

    def _load_scope(self) -> None:
        if not self.scope_path.exists():
            raise FileNotFoundError(f"Scope configuration file not found at: {self.scope_path}")

        with open(self.scope_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        scope_data = data.get("scope", {})
        allowlist = scope_data.get("allowlist", {})

        self.allowed_hostnames: List[str] = [
            h.lower() for h in allowlist.get("hostnames", ["localhost", "127.0.0.1"])
        ]
        cidr_strings: List[str] = allowlist.get("cidrs", ["127.0.0.1/32", "172.16.0.0/12"])
        self.allowed_cidrs: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
            ipaddress.ip_network(c, strict=False) for c in cidr_strings
        ]
        self.allowed_ports: List[int] = allowlist.get(
            "ports", [80, 443, 5000, 8080, 8081, 8082, 3000]
        )

    def check_authorization(self, run_id: Optional[str] = None) -> None:
        """
        Verifies that SENTINEL_I_OWN_THIS_TARGET=true is set in environment.
        Refuses scan execution otherwise.
        """
        auth_val = os.getenv("SENTINEL_I_OWN_THIS_TARGET", "").strip().lower()
        is_authorized = auth_val in ("true", "1", "yes")

        if not is_authorized:
            audit_logger.log(
                event_type="UNAUTHORIZED_EXECUTION_ATTEMPT",
                actor="ScopeGuard",
                details={
                    "error": "SENTINEL_I_OWN_THIS_TARGET environment variable is not set to 'true'"
                },
                run_id=run_id,
            )
            raise UnauthorizedTargetError(
                "Scan refused: SENTINEL_I_OWN_THIS_TARGET must be set to 'true' in .env. "
                "Sentinel strictly prohibits scanning unauthorized targets."
            )

    validate_ownership = check_authorization

    def validate_target(self, target: str, run_id: Optional[str] = None) -> bool:
        """
        Validates target against scope allowlist.
        Supports URLs, IP addresses, hostnames, and local filesystem paths (for SAST).
        """
        # 1. Enforce ownership authorization
        self.check_authorization(run_id=run_id)

        target_str = target.strip()
        if not target_str:
            raise ScopeViolationError("Target specification cannot be empty.")

        # 2. Check if target is a local directory or file path (for SAST tools)
        target_path = Path(target_str)
        if target_path.exists() or not (
            target_str.startswith("http://")
            or target_str.startswith("https://")
            or ":" in target_str
        ):
            try:
                resolved_target = target_path.resolve()
                workspace_root = Path(__file__).resolve().parent.parent.parent
                # Path must be within the project workspace or lab directory
                if (
                    resolved_target == workspace_root
                    or workspace_root in resolved_target.parents
                    or "lab" in resolved_target.parts
                ):
                    audit_logger.log(
                        event_type="SCOPE_VERIFIED",
                        actor="ScopeGuard",
                        details={"target": target_str, "type": "local_filesystem"},
                        run_id=run_id,
                        target=target_str,
                    )
                    return True
            except Exception:
                pass

        # 3. Parse network target (URL or host:port or host)
        hostname: str = ""
        port: Optional[int] = None

        if target_str.startswith("http://") or target_str.startswith("https://"):
            parsed = urlparse(target_str)
            hostname = (parsed.hostname or "").lower()
            port = parsed.port
            if port is None:
                port = 443 if parsed.scheme == "https" else 80
        elif ":" in target_str and not target_str.startswith("/"):
            parts = target_str.split(":")
            hostname = parts[0].lower()
            try:
                port = int(parts[1].split("/")[0])
            except ValueError:
                port = None
        else:
            hostname = target_str.lower()

        # 4. Check port if present
        if port is not None and port not in self.allowed_ports:
            audit_logger.log(
                event_type="SCOPE_VIOLATION",
                actor="ScopeGuard",
                details={"target": target_str, "reason": f"Port {port} is not in allowed ports"},
                run_id=run_id,
                target=target_str,
            )
            raise ScopeViolationError(
                f"Target port {port} for '{target_str}' is OUT OF SCOPE. "
                f"Allowed ports: {self.allowed_ports}"
            )

        # 5. Check hostname allowlist
        if hostname in self.allowed_hostnames:
            audit_logger.log(
                event_type="SCOPE_VERIFIED",
                actor="ScopeGuard",
                details={"target": target_str, "hostname": hostname, "port": port},
                run_id=run_id,
                target=target_str,
            )
            return True

        # 6. Check IP allowlist against CIDRs
        try:
            ip = ipaddress.ip_address(hostname)
            for cidr in self.allowed_cidrs:
                if ip in cidr:
                    audit_logger.log(
                        event_type="SCOPE_VERIFIED",
                        actor="ScopeGuard",
                        details={"target": target_str, "ip": str(ip), "matched_cidr": str(cidr)},
                        run_id=run_id,
                        target=target_str,
                    )
                    return True
        except ValueError:
            # Not an IP string
            pass

        # 7. Reject if no rule matched
        audit_logger.log(
            event_type="SCOPE_VIOLATION",
            actor="ScopeGuard",
            details={
                "target": target_str,
                "hostname": hostname,
                "reason": "Host/IP not in allowed hostnames or CIDR blocks",
            },
            run_id=run_id,
            target=target_str,
        )
        raise ScopeViolationError(
            f"Target '{target_str}' ({hostname}) is OUT OF SCOPE. Scanning rejected by ScopeGuard."
        )


scope_guard = ScopeGuard()
