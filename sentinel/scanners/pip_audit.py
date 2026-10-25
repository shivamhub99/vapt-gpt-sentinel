"""
pip-audit Dependency Vulnerability Scanner Wrapper for VAPT-GPT Sentinel.
Audits Python package manifests (requirements.txt) for known vulnerabilities (CVEs/GHSA).
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

from sentinel.scanners.base import BaseScanner


class PipAuditScanner(BaseScanner):
    """Wraps pip-audit to detect vulnerable dependencies in requirements manifests."""

    tool_name = "pip_audit"

    def run(self, target: str, run_id: str, **kwargs: Any) -> Dict[str, Any]:
        """
        Runs pip-audit -r <target> -f json.
        Target is expected to be a path to requirements.txt or directory containing it.
        """
        target_path = Path(target).resolve()
        req_file = target_path if target_path.is_file() else (target_path / "requirements.txt")

        if not req_file.exists():
            return {
                "dependencies": [],
                "error": f"Requirements file not found at {req_file}",
            }

        cmd = [
            sys.executable,
            "-m",
            "pip_audit",
            "-r",
            str(req_file),
            "-f",
            "json",
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
                return {"dependencies": [], "raw": result.stderr}

            try:
                data = json.loads(raw_stdout)
                return data
            except json.JSONDecodeError:
                return {
                    "dependencies": [],
                    "errors": [f"Malformed JSON: {raw_stdout}"],
                    "raw": raw_stdout,
                }
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"pip-audit timed out after {self.timeout}s on {target}")

    def parse(self, raw_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extracts CVE findings from pip-audit output."""
        data = raw_output.get("data", {})
        dependencies = data.get("dependencies", [])
        parsed_findings: List[Dict[str, Any]] = []

        for dep in dependencies:
            name = dep.get("name")
            version = dep.get("version")
            vulns = dep.get("vulns", [])

            for vuln in vulns:
                vuln_id = vuln.get("id")
                fix_versions = vuln.get("fix_versions", [])
                description = vuln.get("description", "")
                parsed_findings.append(
                    {
                        "tool": "pip_audit",
                        "package": name,
                        "installed_version": version,
                        "vuln_id": vuln_id,
                        "title": f"Vulnerable dependency {name}=={version} ({vuln_id})",
                        "severity": "HIGH",
                        "cwe": "CWE-1395",  # Dependency with Known Vulnerabilities
                        "fix_versions": fix_versions,
                        "description": description,
                        "evidence": f"Package {name}=={version} has known advisory {vuln_id}. Fixed in: {fix_versions}",
                    }
                )

        return parsed_findings
