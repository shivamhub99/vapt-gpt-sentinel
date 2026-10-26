"""
Reflected Cross-Site Scripting (CWE-79) Remediation Fixer.
Sanitizes reflected user-controlled variables in HTML responses using contextual HTML escaping.
"""

import re
from pathlib import Path
from typing import Optional, Tuple

from sentinel.core.schemas import Finding
from sentinel.remediation.fixers.base import BaseFixer


class XSSFixer(BaseFixer):
    """Remediates Cross-Site Scripting by applying HTML output escaping."""

    cwe = "CWE-79"
    category = "Injection"

    def can_fix(self, finding: Finding) -> bool:
        return finding.cwe == "CWE-79" or "xss" in finding.title.lower()

    def apply_template(
        self, finding: Finding, source_code: str, file_path: Path
    ) -> Optional[Tuple[str, str]]:
        if not source_code:
            return None

        # Pattern 1: Greeting endpoint reflection in sentinel-lab-app
        pattern = r'(html_content\s*=\s*f["\'].*?\{(\w+)\}.*?["\'])'
        match = re.search(pattern, source_code)
        if match:
            var_name = match.group(2)
            original_assignment = match.group(1)

            # Ensure escape import is present
            import_statement = "from markupsafe import escape\n"
            if "from markupsafe import escape" not in source_code:
                # Add import after flask import
                source_code = re.sub(
                    r"(from flask import [^\n]+)",
                    r"\1\n" + import_statement,
                    source_code,
                    count=1,
                )

            # Re-find match after import injection
            match = re.search(pattern, source_code)
            if not match:
                return None

            safe_var = f"safe_{var_name}"
            escaped_assignment = (
                f"{safe_var} = escape({var_name})\n    "
                + original_assignment.replace(f"{{{var_name}}}", f"{{{safe_var}}}")
            )

            modified = (
                source_code[: match.start(1)] + escaped_assignment + source_code[match.end(1) :]
            )
            rationale = f"Neutralized reflected XSS by applying markupsafe.escape() to user input variable '{var_name}'."
            return modified, rationale

        return None
