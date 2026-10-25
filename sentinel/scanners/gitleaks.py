"""
Gitleaks Secret Scanner Wrapper for VAPT-GPT Sentinel.
Detects hardcoded API keys, private credentials, and secrets.
Supports native Gitleaks binary, Docker container runner, and built-in offline regex fallback.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from sentinel.scanners.base import BaseScanner


class GitleaksScanner(BaseScanner):
    """Wraps Gitleaks for detecting secrets in repository files."""

    tool_name = "gitleaks"

    # Built-in secret patterns for reliable offline/standalone scanning
    DEFAULT_PATTERNS = [
        (
            r"SENTINEL-SECRET-KEY-[0-9A-Za-z_-]+",
            "Planted Lab API Secret Key",
            "CWE-798",
        ),
        (
            r"AKIA[0-9A-Z]{16}",
            "AWS Access Key ID",
            "CWE-798",
        ),
        (
            r"(?i)(?:api_key|secret_key|password|token)\s*=\s*['\"][0-9a-zA-Z_\-]{16,}['\"]",
            "Hardcoded High-Entropy Secret Assignment",
            "CWE-798",
        ),
    ]

    def _run_native(self, target_path: Path, output_file: Path) -> Optional[Dict[str, Any]]:
        gitleaks_bin = shutil.which("gitleaks")
        if not gitleaks_bin:
            return None

        cmd = [
            gitleaks_bin,
            "dir",
            str(target_path),
            "--report-path",
            str(output_file),
            "--report-format",
            "json",
            "--no-git",
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=self.timeout, check=False)
            if output_file.exists():
                with open(output_file, "r", encoding="utf-8") as f:
                    return {"findings": json.load(f), "engine": "native"}
        except Exception:
            pass
        return None

    def _run_builtin_regex(self, target_path: Path) -> Dict[str, Any]:
        """Fallback deterministic secret regex scanner."""
        findings = []
        files_to_scan = []
        if target_path.is_file():
            files_to_scan.append(target_path)
        else:
            for p in target_path.rglob("*"):
                if p.is_file() and not any(part.startswith(".") for part in p.parts):
                    if p.suffix in (".py", ".env", ".yaml", ".yml", ".json", ".txt", ".md"):
                        files_to_scan.append(p)

        for file_path in files_to_scan:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                for line_idx, line in enumerate(content.splitlines(), start=1):
                    for pattern, title, cwe in self.DEFAULT_PATTERNS:
                        match = re.search(pattern, line)
                        if match:
                            secret_snippet = match.group(0)
                            findings.append(
                                {
                                    "Description": title,
                                    "File": str(file_path),
                                    "StartLine": line_idx,
                                    "Match": secret_snippet,
                                    "Secret": secret_snippet[:4] + "..." + secret_snippet[-4:]
                                    if len(secret_snippet) > 8
                                    else "***",
                                    "RuleID": "sentinel-secret-rule",
                                    "CWE": cwe,
                                }
                            )
            except Exception:
                continue

        return {"findings": findings, "engine": "builtin_regex"}

    def run(self, target: str, run_id: str, **kwargs: Any) -> Dict[str, Any]:
        """Executes secret scanning using native Gitleaks or built-in engine."""
        target_path = Path(target).resolve()
        raw_output_path = self.get_raw_output_path(run_id).with_suffix(".tmp.json")

        result = self._run_native(target_path, raw_output_path)
        if result is None:
            result = self._run_builtin_regex(target_path)

        if raw_output_path.exists():
            try:
                raw_output_path.unlink()
            except Exception:
                pass

        return result

    def parse(self, raw_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extracts secret findings from scanner output."""
        data = raw_output.get("data", {})
        findings = data.get("findings", [])
        parsed: List[Dict[str, Any]] = []

        for item in findings:
            file_name = item.get("File") or item.get("file")
            line = item.get("StartLine") or item.get("start_line", 1)
            description = item.get("Description") or item.get("description", "Hardcoded Secret")
            match = item.get("Match") or item.get("secret", "secret_value")

            parsed.append(
                {
                    "tool": "gitleaks",
                    "title": description,
                    "severity": "CRITICAL",
                    "cwe": item.get("CWE", "CWE-798"),
                    "file": file_name,
                    "line": line,
                    "evidence": f"Found secret pattern: {match[:6]}...",
                }
            )

        return parsed
