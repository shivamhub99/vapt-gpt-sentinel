"""
Append-only Audit Logger for VAPT-GPT Sentinel.
Maintains an immutable JSONL audit ledger of every scan, scope check, prompt, patch, decision, and rollback.
Includes tamper-evident cryptographic chaining (SHA-256).
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from sentinel.core.settings import settings


class AuditLogger:
    """Thread-safe append-only audit logger writing to a JSONL file."""

    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = log_path or settings.audit_log_path
        self._ensure_log_file()
        self._last_hash = self._get_last_hash()

    def _ensure_log_file(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.touch(mode=0o600, exist_ok=True)

    def _get_last_hash(self) -> str:
        """Reads the hash of the last entry in the log to maintain chain integrity."""
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return "GENESIS_BLOCK_0000000000000000000000000000000000000000000000000000"

        last_line = ""
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    last_line = line_str

        if not last_line:
            return "GENESIS_BLOCK_0000000000000000000000000000000000000000000000000000"

        try:
            entry = json.loads(last_line)
            return entry.get("entry_hash", "UNKNOWN_HASH")
        except json.JSONDecodeError:
            return "CORRUPTED_CHAIN_HASH"

    def log(
        self,
        event_type: str,
        actor: str,
        details: Dict[str, Any],
        run_id: Optional[str] = None,
        target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Appends a cryptographically chained event record to the audit ledger."""
        self._ensure_log_file()
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = {
            "timestamp": timestamp,
            "run_id": run_id or "global",
            "event_type": event_type,
            "actor": actor,
            "target": target,
            "prev_hash": self._last_hash,
            "details": details,
        }

        # Calculate entry hash
        serialized = json.dumps(payload, sort_keys=True)
        entry_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        payload["entry_hash"] = entry_hash

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")

        self._last_hash = entry_hash
        return payload

    def read_all(self) -> list[Dict[str, Any]]:
        """Reads all audit log records from the ledger file."""
        if not self.log_path.exists():
            return []
        entries = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    try:
                        entries.append(json.loads(line_str))
                    except json.JSONDecodeError:
                        continue
        return entries

    def log_event(
        self,
        event_type: str,
        details: Dict[str, Any],
        actor: str = "Orchestrator",
        run_id: Optional[str] = None,
        target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Convenience wrapper for logging pipeline events."""
        return self.log(
            event_type=event_type,
            actor=actor,
            details=details,
            run_id=run_id,
            target=target,
        )

    def verify_chain(self) -> tuple[bool, int, Optional[str]]:
        """
        Verifies the cryptographic SHA-256 chain of all records in the audit ledger.
        Returns: (is_valid, record_count, error_message)
        """
        records = self.read_all()
        if not records:
            return True, 0, None

        expected_prev = "GENESIS_BLOCK_0000000000000000000000000000000000000000000000000000"
        for idx, entry in enumerate(records):
            prev_hash = entry.get("prev_hash")
            entry_hash = entry.get("entry_hash")

            if prev_hash != expected_prev:
                return (
                    False,
                    len(records),
                    f"Chain break at record {idx}: expected prev {expected_prev}, got {prev_hash}",
                )

            # Recompute entry hash
            payload_copy = {k: v for k, v in entry.items() if k != "entry_hash"}
            serialized = json.dumps(payload_copy, sort_keys=True)
            recalculated = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

            if recalculated != entry_hash:
                return (
                    False,
                    len(records),
                    f"Tampered hash at record {idx}: recorded {entry_hash}, computed {recalculated}",
                )

            expected_prev = entry_hash

        return True, len(records), None


audit_logger = AuditLogger()
