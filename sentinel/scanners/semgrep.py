"""
Semgrep SAST Scanner Wrapper for VAPT-GPT Sentinel.
Executes Semgrep in non-destructive mode using OWASP rulesets and parses findings into canonical formats.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

from sentinel.scanners.base import BaseScanner


class SemgrepScanner(BaseScanner):
    """Wraps Semgrep SAST scanner."""

    tool_name = "semgrep"

    def __init__(self, config: str = "p/owasp-top-ten", timeout_seconds: int = 300):
        super().__init__(timeout_seconds=timeout_seconds)
        self.config = config

    def _get_semgrep_cmd(self) -> List[str]:
        # Check if semgrep executable is directly on PATH or in venv Scripts
        venv_bin = Path(sys.executable).parent / "semgrep.exe"
        if venv_bin.exists():
            return [str(venv_bin)]
        path_bin = shutil.which("semgrep")
        if path_bin:
            return [path_bin]
        return [sys.executable, "-m", "semgrep"]

    def run(self, target: str, run_id: str, **kwargs: Any) -> Dict[str, Any]:
        """Runs semgrep scan --json against target."""
        target_path = Path(target).resolve()
        rule_config = kwargs.get("config", self.config)

        cmd = self._get_semgrep_cmd() + [
            "scan",
            "--config",
            rule_config,
            "--json",
            "--quiet",
            str(target_path),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            raw_stdout = result.stdout.strip()
            if not raw_stdout:
                return {
                    "results": [],
                    "errors": [result.stderr] if result.stderr else [],
                    "paths": {"scanned": [str(target_path)]},
                }

            try:
                data = json.loads(raw_stdout)
                return data
            except json.JSONDecodeError:
                return {
                    "results": [],
                    "errors": [f"Malformed JSON from semgrep: {raw_stdout}"],
                    "raw": raw_stdout,
                }
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"Semgrep scan timed out after {self.timeout}s on {target}")

    def parse(self, raw_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extracts finding records from Semgrep raw output."""
        data = raw_output.get("data", {})
        results = data.get("results", [])
        parsed_findings: List[Dict[str, Any]] = []

        for item in results:
            check_id = item.get("check_id", "")
            extra = item.get("extra", {})
            metadata = extra.get("metadata", {})
            cwe_list = metadata.get("cwe", [])
            cwe = cwe_list[0] if (cwe_list and isinstance(cwe_list, list)) else "CWE-Unknown"

            start_line = item.get("start", {}).get("line")
            parsed_findings.append(
                {
                    "tool": "semgrep",
                    "check_id": check_id,
                    "title": extra.get("message", check_id),
                    "severity": extra.get("severity", "WARNING").upper(),
                    "cwe": cwe,
                    "owasp": metadata.get("owasp", []),
                    "file": item.get("path"),
                    "line": start_line,
                    "evidence": extra.get("lines", ""),
                }
            )

        return parsed_findings
