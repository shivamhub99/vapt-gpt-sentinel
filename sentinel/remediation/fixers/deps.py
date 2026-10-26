"""
Vulnerable Dependency (CWE-1395) Remediation Fixer.
Bumps pinned vulnerable dependencies in requirements.txt to secure patched versions.
"""

import re
from pathlib import Path
from typing import Optional, Tuple

from sentinel.core.schemas import Finding
from sentinel.remediation.fixers.base import BaseFixer

KNOWN_PATCH_VERSIONS = {
    "werkzeug": ">=2.3.8",
    "requests": ">=2.31.0",
    "urllib3": ">=1.26.19",
    "flask": ">=2.3.3",
    "jinja2": ">=3.1.3",
}


class DependencyFixer(BaseFixer):
    """Remediates supply chain CVEs by updating dependency manifests."""

    cwe = "CWE-1395"
    category = "SupplyChain"

    def can_fix(self, finding: Finding) -> bool:
        return (
            finding.cwe == "CWE-1395"
            or "dependency" in finding.title.lower()
            or (finding.file and "requirements.txt" in finding.file)
        )

    def apply_template(
        self, finding: Finding, source_code: str, file_path: Path
    ) -> Optional[Tuple[str, str]]:
        if not source_code:
            return None

        # Check if target is a requirements file or locate requirements.txt in directory
        if "requirements" not in file_path.name.lower():
            req_path = file_path.parent / "requirements.txt"
            if req_path.exists():
                source_code = req_path.read_text(encoding="utf-8")
                file_path = req_path
            else:
                return None

        package_name = finding.raw_tool_data.get("package") or finding.raw_tool_data.get("PkgName")
        fix_version = None

        if package_name:
            fix_version = KNOWN_PATCH_VERSIONS.get(package_name.lower())

        modified = source_code
        applied_fixes = []

        # If specific package identified
        if package_name and fix_version:
            pattern = rf"(?i)^{package_name}\s*==\s*[^\n\r]+"
            if re.search(pattern, modified, re.MULTILINE):
                modified = re.sub(
                    pattern, f"{package_name}{fix_version}", modified, flags=re.MULTILINE
                )
                applied_fixes.append(f"{package_name}{fix_version}")

        # General sweep for known vulnerable lab packages
        for pkg, target_spec in KNOWN_PATCH_VERSIONS.items():
            pattern = rf"(?i)^{pkg}\s*==\s*2\.[0-9.]+"
            if re.search(pattern, modified, re.MULTILINE):
                modified = re.sub(pattern, f"{pkg}{target_spec}", modified, flags=re.MULTILINE)
                applied_fixes.append(f"{pkg}{target_spec}")

        if modified != source_code:
            fixes_str = ", ".join(set(applied_fixes))
            rationale = f"Upgraded vulnerable dependencies in requirements.txt to patched versions: {fixes_str}."
            return modified, rationale

        return None
