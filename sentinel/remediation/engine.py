"""
Central Remediation Engine for VAPT-GPT Sentinel.
Coordinates finding dispatch to specialized fixers, isolated Git sandbox branching,
patch application, and audit logging.
"""

from pathlib import Path
from typing import List, Optional, Tuple

import git

from sentinel.core.audit_log import audit_logger
from sentinel.core.database import db
from sentinel.core.schemas import Finding, FindingStatus, Patch
from sentinel.remediation.fixers import FIXER_CLASSES, BaseFixer
from sentinel.remediation.patch_apply import sandbox_manager

# Categories strictly requiring human approval (never auto-remediated blindly)
RISKY_CATEGORIES = {
    "CWE-287": "Authentication Bypass / Core Auth Logic",
    "CWE-284": "Access Control Logic",
    "CWE-639": "Insecure Direct Object Reference / Ownership Policy",
}


class RemediationGatedError(Exception):
    """Raised when a finding belongs to a security-critical category requiring manual human approval."""


class RemediationEngine:
    """Orchestrates vulnerability fix generation and sandboxed Git branch application."""

    def __init__(self, fixers: Optional[List[BaseFixer]] = None):
        self.fixers: List[BaseFixer] = fixers or [cls() for cls in FIXER_CLASSES]

    def get_fixer(self, finding: Finding) -> Optional[BaseFixer]:
        """Finds the first registered fixer capable of resolving this finding."""
        for fixer in self.fixers:
            if fixer.can_fix(finding):
                return fixer
        return None

    def remediate(
        self,
        finding: Finding,
        target_dir: Path,
        attempt: int = 1,
        failure_feedback: Optional[str] = None,
    ) -> Tuple[Patch, git.Repo]:
        """
        Generates and applies a secure patch onto an isolated Git sandbox branch.
        Never touches the original target repository directly.
        """
        # Hard Safety Rule 5: Risky categories require human approval
        if finding.cwe in RISKY_CATEGORIES:
            audit_logger.log(
                event_type="REMEDIATION_GATED",
                actor="RemediationEngine",
                details={
                    "finding_id": finding.id,
                    "cwe": finding.cwe,
                    "reason": f"Category '{RISKY_CATEGORIES[finding.cwe]}' requires human review.",
                },
            )
            finding.status = FindingStatus.NEEDS_HUMAN
            db.update_finding_status(finding.id, FindingStatus.NEEDS_HUMAN)
            raise RemediationGatedError(
                f"Finding {finding.id} ({finding.cwe}) belongs to gated category '{RISKY_CATEGORIES[finding.cwe]}'. "
                f"Manual security review and authorization required."
            )

        fixer = self.get_fixer(finding)
        if not fixer:
            raise ValueError(
                f"No compatible remediation fixer found for finding {finding.id} ({finding.cwe})"
            )

        # 1. Setup isolated sandbox repository
        repo = sandbox_manager.prepare_sandbox(target_dir)
        sandbox_path = Path(repo.working_dir)

        # 2. Create isolated Git branch
        branch_name = sandbox_manager.create_fix_branch(repo, finding.id, attempt=attempt)

        # 3. Generate patch
        audit_logger.log(
            event_type="PATCH_PROPOSED",
            actor=f"{fixer.__class__.__name__}",
            details={"finding_id": finding.id, "attempt": attempt, "branch": branch_name},
        )
        patch = fixer.fix(
            finding=finding,
            sandbox_dir=sandbox_path,
            attempt=attempt,
            failure_feedback=failure_feedback,
        )

        # 4. Apply unified diff to branch
        sandbox_manager.apply_diff(
            repo=repo,
            diff_text=patch.diff,
            finding_id=finding.id,
            rationale=patch.rationale,
        )

        # 5. Record patch in database
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO patches (id, finding_id, diff, branch, rationale, attempt, generated_by, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                patch.id,
                patch.finding_id,
                patch.diff,
                branch_name,
                patch.rationale,
                patch.attempt,
                patch.generated_by,
                patch.timestamp.isoformat(),
            ),
        )
        conn.commit()
        conn.close()

        finding.status = FindingStatus.PATCH_IN_PROGRESS
        db.update_finding_status(finding.id, FindingStatus.PATCH_IN_PROGRESS)

        return patch, repo


remediation_engine = RemediationEngine()
