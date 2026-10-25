"""
Finding Deduplication Engine for VAPT-GPT Sentinel.
Identifies and merges duplicate vulnerability findings reported across multiple scanners
at the same source code location or network endpoint.
"""

import hashlib
from pathlib import Path
from typing import List, Optional

from sentinel.core.schemas import Finding, Severity

# Severity priority ordering for resolving conflicts
SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def normalize_file_path(file_path: Optional[str]) -> str:
    """Normalizes file path to relative posix format for comparison."""
    if not file_path:
        return ""
    p = Path(file_path)
    return p.name.lower()


def normalize_endpoint(endpoint: Optional[str]) -> str:
    """Normalizes URL endpoint for web finding comparison."""
    if not endpoint:
        return ""
    # Strip protocol and query params for root path matching
    clean = endpoint.split("?")[0].rstrip("/").lower()
    return clean


def are_findings_duplicate(f1: Finding, f2: Finding) -> bool:
    """
    Determines if two findings represent the same underlying vulnerability.
    """
    # 1. CWE must match (or both are closely related injection/secret CWEs)
    if f1.cwe != f2.cwe:
        return False

    # 2. Case: Dependency vulnerability (same CVE or package)
    pkg1 = f1.raw_tool_data.get("package") or f1.raw_tool_data.get("PkgName")
    pkg2 = f2.raw_tool_data.get("package") or f2.raw_tool_data.get("PkgName")
    vuln_id1 = f1.raw_tool_data.get("vuln_id") or f1.raw_tool_data.get("VulnerabilityID")
    vuln_id2 = f2.raw_tool_data.get("vuln_id") or f2.raw_tool_data.get("VulnerabilityID")

    if pkg1 and pkg2 and pkg1.lower() == pkg2.lower():
        if vuln_id1 and vuln_id2:
            return vuln_id1.lower() == vuln_id2.lower()
        return True

    # 3. Case: Source code vulnerability (same file and nearby line number)
    file1 = normalize_file_path(f1.file)
    file2 = normalize_file_path(f2.file)
    if file1 and file2 and file1 == file2:
        if f1.line is not None and f2.line is not None:
            # Within 15 lines of each other in the same file
            if abs(f1.line - f2.line) <= 15:
                return True
        else:
            return True

    # 4. Case: Web endpoint vulnerability (same URL endpoint and parameter/check)
    ep1 = normalize_endpoint(f1.endpoint)
    ep2 = normalize_endpoint(f2.endpoint)
    if ep1 and ep2 and ep1 == ep2:
        # Same parameter or header issue
        if f1.param and f2.param and f1.param.lower() == f2.param.lower():
            return True
        if not f1.param and not f2.param:
            return True

    return False


def merge_findings(primary: Finding, secondary: Finding) -> Finding:
    """
    Merges secondary finding into primary finding, preserving combined tools and evidence.
    """
    # Combine tool names
    primary_tools = set(primary.tool.split(","))
    secondary_tools = set(secondary.tool.split(","))
    all_tools = sorted(primary_tools.union(secondary_tools))
    merged_tools = ",".join(all_tools)

    # Pick highest severity
    p_sev_rank = SEVERITY_ORDER.get(primary.severity, 0)
    s_sev_rank = SEVERITY_ORDER.get(secondary.severity, 0)
    merged_severity = primary.severity if p_sev_rank >= s_sev_rank else secondary.severity

    # Merge evidence
    merged_evidence = primary.evidence
    if secondary.evidence and secondary.evidence not in primary.evidence:
        merged_evidence = f"{primary.evidence} | [From {secondary.tool}]: {secondary.evidence}"

    # Retain best line number
    merged_line = primary.line or secondary.line

    # Combine raw data
    merged_raw = dict(primary.raw_tool_data)
    merged_raw[f"secondary_{secondary.tool}"] = secondary.raw_tool_data

    return Finding(
        id=primary.id,
        tool=merged_tools,
        cwe=primary.cwe,
        owasp=primary.owasp or secondary.owasp,
        title=primary.title,
        severity=merged_severity,
        cvss=primary.cvss or secondary.cvss,
        epss=primary.epss or secondary.epss,
        file=primary.file or secondary.file,
        line=merged_line,
        endpoint=primary.endpoint or secondary.endpoint,
        param=primary.param or secondary.param,
        evidence=merged_evidence,
        status=primary.status,
        first_seen=primary.first_seen,
        raw_tool_data=merged_raw,
    )


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """
    Deduplicates a list of findings across multiple tools.
    Returns consolidated findings with merged evidence and tool sources.
    """
    deduped: List[Finding] = []

    for finding in findings:
        matched = False
        for idx, existing in enumerate(deduped):
            if are_findings_duplicate(existing, finding):
                deduped[idx] = merge_findings(existing, finding)
                matched = True
                break
        if not matched:
            # Generate deterministic finding ID
            loc_str = f"{finding.cwe}_{normalize_file_path(finding.file)}_{finding.line}_{normalize_endpoint(finding.endpoint)}"
            loc_hash = hashlib.md5(loc_str.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]

            cwe_clean = finding.cwe.lower().replace("-", "_")
            unique_id = f"finding_{cwe_clean}_{loc_hash}"
            finding.id = unique_id
            deduped.append(finding)

    return deduped
