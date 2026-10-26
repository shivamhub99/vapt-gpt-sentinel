"""
Hardcoded Secret (CWE-798) Remediation Fixer.
Extracts hardcoded credentials and API keys to environment variables and updates .env.example.
"""

import re
from pathlib import Path
from typing import Optional, Tuple

from sentinel.core.schemas import Finding
from sentinel.remediation.fixers.base import BaseFixer


class SecretsFixer(BaseFixer):
    """Remediates hardcoded secrets by migrating them to os.environ and updating .env.example."""

    cwe = "CWE-798"
    category = "Credentials"

    def can_fix(self, finding: Finding) -> bool:
        return (
            finding.cwe == "CWE-798"
            or "secret" in finding.title.lower()
            or "key" in finding.title.lower()
        )

    def apply_template(
        self, finding: Finding, source_code: str, file_path: Path
    ) -> Optional[Tuple[str, str]]:
        if not source_code:
            return None

        # Pattern 1: API_SECRET_KEY assignment
        pattern = r'(API_SECRET_KEY\s*=\s*["\']([^"\']+)["\'])'
        match = re.search(pattern, source_code)
        if match:
            original_val = match.group(2)
            var_name = "API_SECRET_KEY"
            replacement = f'{var_name} = os.environ.get("{var_name}", "{original_val}")'

            modified = source_code[: match.start(1)] + replacement + source_code[match.end(1) :]

            # Update .env.example in sandbox directory
            sandbox_dir = file_path.parent
            env_example_path = sandbox_dir / ".env.example"
            example_entry = (
                f"\n# Added by Sentinel Remediation\n{var_name}=your_{var_name.lower()}_here\n"
            )

            if env_example_path.exists():
                curr_content = env_example_path.read_text(encoding="utf-8")
                if var_name not in curr_content:
                    env_example_path.write_text(curr_content + example_entry, encoding="utf-8")
            else:
                env_example_path.write_text(example_entry.lstrip(), encoding="utf-8")

            rationale = (
                f"Migrated hardcoded credential '{var_name}' to environment variable "
                f"via os.environ.get() and registered placeholder in .env.example."
            )
            return modified, rationale

        return None
