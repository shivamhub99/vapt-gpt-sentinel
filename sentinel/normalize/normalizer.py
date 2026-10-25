"""
Finding Normalization Pipeline for VAPT-GPT Sentinel.
Ingests raw JSON reports from all wrapped scanning tools, maps them to canonical CWE and OWASP categories,
deduplicates overlapping findings across tools, and persists to SQLite.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from sentinel.core.database import db
from sentinel.core.schemas import Finding, FindingStatus, Severity
from sentinel.core.settings import settings
from sentinel.normalize.cwe_map import get_owasp_category, normalize_cwe
from sentinel.normalize.dedupe import deduplicate_findings
from sentinel.scanners import SCANNER_REGISTRY


class Normalizer:
    """
    Normalizes heterogeneous tool outputs into canonical Finding objects.
    """

    def __init__(self, runs_dir: Optional[Path] = None):
        self.runs_dir = runs_dir or settings.runs_dir

    def _normalize_severity(self, raw_sev: Any) -> Severity:
        """Converts diverse scanner severity strings/integers to Severity enum."""
        if not raw_sev:
            return Severity.MEDIUM
        s = str(raw_sev).strip().upper()
        if "CRIT" in s:
            return Severity.CRITICAL
        if "HIGH" in s or s in ("3", "ERROR"):
            return Severity.HIGH
        if "MED" in s or s in ("2", "WARNING", "WARN"):
            return Severity.MEDIUM
        if "LOW" in s or s == "1":
            return Severity.LOW
        if "INFO" in s or s == "0":
            return Severity.INFO
        return Severity.MEDIUM

    def normalize_tool_finding(self, tool_name: str, raw_item: Dict[str, Any]) -> Finding:
        """Converts a single parsed tool dictionary into a canonical Finding object."""
        rule_id = str(
            raw_item.get("test_id")
            or raw_item.get("check_id")
            or raw_item.get("plugin_id")
            or raw_item.get("check")
            or raw_item.get("vuln_id")
            or raw_item.get("RuleID")
            or ""
        )
        raw_cwe = raw_item.get("cwe") or raw_item.get("cweid") or raw_item.get("CWE")

        cwe = normalize_cwe(tool=tool_name, raw_rule=rule_id, raw_cwe=raw_cwe)
        owasp = get_owasp_category(cwe)
        severity = self._normalize_severity(raw_item.get("severity") or raw_item.get("Severity"))

        title = (
            raw_item.get("title")
            or raw_item.get("issue_text")
            or raw_item.get("Description")
            or f"{cwe} detected by {tool_name}"
        )
        evidence = raw_item.get("evidence") or raw_item.get("Match") or raw_item.get("code") or ""
        file_path = raw_item.get("file") or raw_item.get("filename") or raw_item.get("File")
        line = raw_item.get("line") or raw_item.get("line_number") or raw_item.get("StartLine")
        endpoint = raw_item.get("endpoint") or raw_item.get("uri")
        param = raw_item.get("param")

        return Finding(
            id=f"tmp_{tool_name}_{cwe.lower()}",
            tool=tool_name,
            cwe=cwe,
            owasp=owasp,
            title=title,
            severity=severity,
            file=str(file_path) if file_path else None,
            line=int(line) if line is not None else None,
            endpoint=str(endpoint) if endpoint else None,
            param=str(param) if param else None,
            evidence=str(evidence),
            status=FindingStatus.OPEN,
            raw_tool_data=raw_item,
        )

    def normalize_run(self, run_id: str, persist: bool = True) -> List[Finding]:
        """
        Ingests all raw tool output JSON files from runs/<run_id>/raw/
        and normalizes, deduplicates, and persists findings to SQLite.
        """
        raw_dir = self.runs_dir / run_id / "raw"
        if not raw_dir.exists():
            return []

        all_findings: List[Finding] = []

        for raw_file in raw_dir.glob("*.json"):
            tool_name = raw_file.stem.lower()
            try:
                with open(raw_file, "r", encoding="utf-8") as f:
                    content = json.load(f)

                # Extract parsed findings via scanner wrapper parser if available
                scanner_cls = SCANNER_REGISTRY.get(tool_name)
                parsed_items: List[Dict[str, Any]] = []
                if scanner_cls:
                    scanner = scanner_cls()
                    parsed_items = scanner.parse(content)
                elif "data" in content and isinstance(content["data"], dict):
                    parsed_items = content["data"].get("findings", [])
                elif isinstance(content, list):
                    parsed_items = content

                for item in parsed_items:
                    finding = self.normalize_tool_finding(tool_name=tool_name, raw_item=item)
                    all_findings.append(finding)
            except Exception:
                continue

        # Deduplicate across tools
        deduped = deduplicate_findings(all_findings)

        # Persist to SQLite
        if persist:
            db.save_findings(deduped, run_id=run_id)
            target = "lab-target"
            db.save_run(run_id=run_id, target=target, findings_count=len(deduped))

        return deduped


normalizer = Normalizer()
