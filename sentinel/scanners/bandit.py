"""
Bandit SAST Scanner Wrapper for VAPT-GPT Sentinel.
Executes Bandit against Python source trees in non-destructive mode and captures JSON reports.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

from sentinel.scanners.base import BaseScanner


class BanditScanner(BaseScanner):
    """Wraps the Bandit SAST tool for scanning Python repositories."""

    tool_name = "bandit"

    def run(self, target: str, run_id: str, **kwargs: Any) -> Dict[str, Any]:
        """
        Runs bandit -r <target> -f json.
        Target is expected to be a directory or file path.
        """
        target_path = Path(target).resolve()
        cmd = [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            str(target_path),
            "-f",
            "json",
            "-q",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,  # Bandit exits with 1 if issues found
            )
            raw_stdout = result.stdout.strip()
            if not raw_stdout:
                # If bandit produced no output, check stderr
                return {"results": [], "errors": [result.stderr], "metrics": {}}

            try:
                data = json.loads(raw_stdout)
                return data
            except json.JSONDecodeError:
                return {
                    "results": [],
                    "errors": [f"Malformed JSON from bandit: {raw_stdout}"],
                    "raw": raw_stdout,
                }
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"Bandit scan timed out after {self.timeout} seconds on {target}")

    def parse(self, raw_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extracts findings list from Bandit JSON output."""
        data = raw_output.get("data", {})
        results = data.get("results", [])
        parsed_findings: List[Dict[str, Any]] = []

        for item in results:
            parsed_findings.append(
                {
                    "tool": "bandit",
                    "test_id": item.get("test_id"),
                    "title": item.get("issue_text"),
                    "severity": item.get("issue_severity", "LOW").upper(),
                    "confidence": item.get("issue_confidence", "LOW").upper(),
                    "cwe": f"CWE-{item.get('issue_cwe', {}).get('id')}"
                    if item.get("issue_cwe")
                    else "CWE-Unknown",
                    "file": item.get("filename"),
                    "line": item.get("line_number"),
                    "code": item.get("code"),
                    "evidence": item.get("issue_text"),
                }
            )

        return parsed_findings
