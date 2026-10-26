"""
SQL Injection (CWE-89) Remediation Fixer.
Transforms unescaped dynamic SQL string interpolations into safe parameterized queries.
"""

import re
from pathlib import Path
from typing import Optional, Tuple

from sentinel.core.schemas import Finding
from sentinel.remediation.fixers.base import BaseFixer


class SQLInjectionFixer(BaseFixer):
    """Remediates SQL Injection vulnerabilities by parameterizing raw SQL executions."""

    cwe = "CWE-89"
    category = "Injection"

    def can_fix(self, finding: Finding) -> bool:
        return finding.cwe == "CWE-89" or "sql" in finding.title.lower()

    def apply_template(
        self, finding: Finding, source_code: str, file_path: Path
    ) -> Optional[Tuple[str, str]]:
        if not source_code:
            return None

        # Pattern 1: Specific sentinel-lab-app search route query
        pattern_1 = r'raw_sql\s*=\s*f["\']SELECT\s+id,\s*name,\s*description,\s*price\s+FROM\s+products\s+WHERE\s+name\s+LIKE\s+[\'"]%\{(\w+)\}%[\'"][\'"]\s*\n\s*cursor\.execute\(raw_sql\)'
        match_1 = re.search(pattern_1, source_code)
        if match_1:
            var_name = match_1.group(1)
            replacement = (
                f'query_param = f"%{{{var_name}}}%"\n'
                f'    cursor.execute("SELECT id, name, description, price FROM products WHERE name LIKE ?", (query_param,))'
            )
            modified = source_code[: match_1.start()] + replacement + source_code[match_1.end() :]
            rationale = "Parameterized raw SQL query execution using SQLite '?' query binding."
            return modified, rationale

        # Pattern 2: Generic cursor.execute(f"SELECT ...")
        pattern_2 = r'cursor\.execute\(f["\']SELECT\s+(.*?)\s+WHERE\s+(\w+)\s*=\s*[\'"]\{(\w+)\}[\'"][\'"]\)'
        match_2 = re.search(pattern_2, source_code)
        if match_2:
            cols, field, var_name = match_2.group(1), match_2.group(2), match_2.group(3)
            replacement = f'cursor.execute("SELECT {cols} WHERE {field} = ?", ({var_name},))'
            modified = source_code[: match_2.start()] + replacement + source_code[match_2.end() :]
            rationale = (
                f"Parameterized dynamic query condition on column '{field}' with bound parameters."
            )
            return modified, rationale

        return None
