"""
Base Scanner Specification for VAPT-GPT Sentinel.
Every scanner wrapper must inherit from BaseScanner, enforce ScopeGuard validation
prior to network activity, respect execution timeouts, and save raw JSON under runs/<run_id>/raw/.
"""

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sentinel.core.audit_log import audit_logger
from sentinel.core.scope_guard import scope_guard
from sentinel.core.settings import settings


class BaseScanner(ABC):
    """
    Abstract base scanner wrapper.
    Guarantees:
    1. ScopeGuard validation before any network or filesystem scanning.
    2. Enforced execution timeouts.
    3. Structured raw JSON persistence to `runs/<run_id>/raw/<tool_name>.json`.
    4. Cryptographically linked audit trail entry.
    """

    tool_name: str = "base"

    def __init__(self, timeout_seconds: Optional[int] = None):
        self.timeout = timeout_seconds or settings.timeout_seconds

    def get_raw_output_path(self, run_id: str) -> Path:
        """Returns the destination path for raw scanner output."""
        output_dir = settings.runs_dir / run_id / "raw"
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir / f"{self.tool_name}.json"

    def save_raw_output(self, run_id: str, data: Dict[str, Any]) -> Path:
        """Persists raw scanner output as structured JSON."""
        path = self.get_raw_output_path(run_id)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def execute(self, target: str, run_id: str, **kwargs: Any) -> Dict[str, Any]:
        """
        Public entrypoint. Validates scope, executes scan, persists raw output, and audits.
        """
        # HARD SAFETY RULE 1: ScopeGuard MUST be called before any activity
        scope_guard.validate_target(target, run_id=run_id)

        audit_logger.log(
            event_type="SCAN_INIT",
            actor=f"{self.tool_name.capitalize()}Scanner",
            details={"target": target, "timeout": self.timeout, "kwargs": kwargs},
            run_id=run_id,
            target=target,
        )

        start_time = datetime.now(timezone.utc)
        try:
            raw_data = self.run(target=target, run_id=run_id, **kwargs)
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()

            payload = {
                "tool": self.tool_name,
                "target": target,
                "run_id": run_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": duration,
                "success": True,
                "data": raw_data,
            }
        except Exception as exc:
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            payload = {
                "tool": self.tool_name,
                "target": target,
                "run_id": run_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": duration,
                "success": False,
                "error": str(exc),
                "data": {},
            }
            audit_logger.log(
                event_type="SCAN_FAILED",
                actor=f"{self.tool_name.capitalize()}Scanner",
                details={"error": str(exc), "duration": duration},
                run_id=run_id,
                target=target,
            )
            self.save_raw_output(run_id, payload)
            raise

        output_path = self.save_raw_output(run_id, payload)

        audit_logger.log(
            event_type="SCAN_COMPLETE",
            actor=f"{self.tool_name.capitalize()}Scanner",
            details={
                "target": target,
                "duration": duration,
                "output_file": str(output_path),
            },
            run_id=run_id,
            target=target,
        )

        return payload

    @abstractmethod
    def run(self, target: str, run_id: str, **kwargs: Any) -> Dict[str, Any]:
        """Performs the actual scanner execution and returns raw data dictionary."""

    @abstractmethod
    def parse(self, raw_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extracts tool-specific raw finding structures from the scan output."""
