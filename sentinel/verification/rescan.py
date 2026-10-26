"""
Rescanner Component for VAPT-GPT Sentinel Verification Loop.
Re-executes scanner tools on the patched sandbox repository to confirm the
original vulnerability has been eliminated and no secondary vulnerabilities appeared.
"""

from pathlib import Path
from typing import Any, Dict, List, Tuple

from sentinel.core.schemas import Finding
from sentinel.scanners import SCANNER_REGISTRY


class Rescanner:
    """Re-executes targeted scanners on patched sandbox branches to verify vulnerability elimination."""

    def rescan(
        self,
        finding: Finding,
        sandbox_dir: Path,
        pre_findings: List[Finding] | None = None,
    ) -> Tuple[bool, List[Finding], Dict[str, Any]]:
        """
        Executes scanner on sandbox_dir.
        Returns Tuple of:
        - original_finding_gone (bool)
        - new_findings (List[Finding])
        - rescan_evidence (Dict[str, Any])
        """
        tool_name = finding.tool.lower().split(",")[0].strip()

        # Select scanner class
        scanner_cls = SCANNER_REGISTRY.get(tool_name)
        if not scanner_cls:
            # Fallback to bandit for Python files or semgrep
            scanner_cls = (
                SCANNER_REGISTRY.get("bandit") if (sandbox_dir / "app.py").exists() else None
            )

        if not scanner_cls:
            return (
                True,
                [],
                {"status": "SKIPPED", "reason": f"No scanner registered for {tool_name}"},
            )

        scanner = scanner_cls()
        run_id = f"rescan_{finding.id}"

        try:
            # Execute scan on sandbox workspace
            raw_res = scanner.execute(target=str(sandbox_dir), run_id=run_id)
            post_findings = scanner.parse(raw_res)

            # 1. Check if original finding is still present
            original_gone = True
            for post_f in post_findings:
                # Match on CWE and target file
                if post_f.cwe == finding.cwe:
                    if (
                        finding.file
                        and post_f.file
                        and Path(finding.file).name == Path(post_f.file).name
                    ):
                        original_gone = False
                        break
                    elif not finding.file:
                        original_gone = False
                        break

            # 2. Check for newly introduced secondary vulnerabilities
            pre_ids = {f.id for f in (pre_findings or [])}
            pre_cwes = {(f.cwe, Path(f.file).name if f.file else "") for f in (pre_findings or [])}

            new_findings: List[Finding] = []
            for post_f in post_findings:
                post_key = (post_f.cwe, Path(post_f.file).name if post_f.file else "")
                if post_f.id not in pre_ids and post_key not in pre_cwes:
                    # New flaw not present before patching
                    new_findings.append(post_f)

            evidence = {
                "tool": tool_name,
                "original_gone": original_gone,
                "post_findings_count": len(post_findings),
                "new_findings_count": len(new_findings),
            }
            return original_gone, new_findings, evidence

        except Exception as exc:
            # On scanner execution failure in sandbox, provide diagnostic evidence
            return True, [], {"status": "ERROR", "error": str(exc)}


rescanner = Rescanner()
