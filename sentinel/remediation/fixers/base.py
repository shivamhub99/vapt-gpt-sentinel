"""
Base Fixer Specification for VAPT-GPT Sentinel.
Every fixer attempts a deterministic AST/regex template first;
if not applicable, it queries the configured LLM provider for a validated unified diff.
"""

import difflib
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Tuple

from sentinel.core.schemas import Finding, Patch
from sentinel.llm import LLMProvider, get_llm_provider


class BaseFixer(ABC):
    """Abstract vulnerability remediation fixer."""

    cwe: str = "CWE-Unknown"
    category: str = "General"

    def __init__(self, llm_provider: Optional[LLMProvider] = None):
        self.llm = llm_provider or get_llm_provider()

    @abstractmethod
    def can_fix(self, finding: Finding) -> bool:
        """Determines if this fixer is capable of remediating the finding."""

    @abstractmethod
    def apply_template(
        self, finding: Finding, source_code: str, file_path: Path
    ) -> Optional[Tuple[str, str]]:
        """
        Attempts a deterministic code transformation.
        Returns Tuple of (modified_source_code, rationale) if successful, None otherwise.
        """

    def generate_unified_diff(
        self, original_text: str, modified_text: str, file_rel_path: str
    ) -> str:
        """Generates a standard unified diff between original and modified file contents."""
        orig_lines = original_text.splitlines(keepends=True)
        mod_lines = modified_text.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            mod_lines,
            fromfile=f"a/{file_rel_path}",
            tofile=f"b/{file_rel_path}",
        )
        return "".join(diff)

    def fix(
        self,
        finding: Finding,
        sandbox_dir: Path,
        attempt: int = 1,
        failure_feedback: Optional[str] = None,
    ) -> Patch:
        """
        Generates a Patch for the finding:
        1. Tries deterministic template.
        2. Falls back to LLM unified diff prompt if template does not apply.
        """
        file_path_str = finding.file or "app.py"
        target_file = sandbox_dir / Path(file_path_str).name
        if not target_file.exists():
            # Search for file inside sandbox
            matches = list(sandbox_dir.rglob(Path(file_path_str).name))
            if matches:
                target_file = matches[0]

        rel_path = (
            target_file.relative_to(sandbox_dir).as_posix()
            if target_file.exists()
            else Path(file_path_str).name
        )
        original_source = (
            target_file.read_text(encoding="utf-8", errors="ignore") if target_file.exists() else ""
        )

        # Step 1: Try deterministic template
        template_res = self.apply_template(finding, original_source, target_file)
        if template_res is not None:
            mod_source, rationale = template_res
            diff_text = self.generate_unified_diff(original_source, mod_source, rel_path)
            return Patch(
                id=f"patch_{finding.id}_att{attempt}",
                finding_id=finding.id,
                diff=diff_text,
                branch=f"sentinel/fix-{finding.id.replace('_', '-').lower()}-att{attempt}",
                rationale=rationale,
                attempt=attempt,
                generated_by="template",
            )

        # Step 2: Fall back to LLM provider
        llm_res = self.llm.generate_patch(
            cwe=finding.cwe,
            finding_title=finding.title,
            file_path=rel_path,
            source_code=original_source,
            evidence=finding.evidence,
            failure_feedback=failure_feedback,
        )

        return Patch(
            id=f"patch_{finding.id}_att{attempt}",
            finding_id=finding.id,
            diff=llm_res.get("diff", ""),
            branch=f"sentinel/fix-{finding.id.replace('_', '-').lower()}-att{attempt}",
            rationale=llm_res.get(
                "rationale", f"Remediated {finding.cwe} using LLM patch generator."
            ),
            attempt=attempt,
            generated_by="llm",
        )
