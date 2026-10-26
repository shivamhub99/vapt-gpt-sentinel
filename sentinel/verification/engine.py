"""
Verification Engine for VAPT-GPT Sentinel.
Orchestrates the 4-phase deterministic verification loop:
PATCHED -> RUN_TESTS -> SECURITY_REGRESSION -> RESCAN -> DECISION -> MERGE or ROLLBACK.
Coordinates automatic rollback and retry diagnostics up to max 3 attempts.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import git

from sentinel.core.audit_log import audit_logger
from sentinel.core.database import db
from sentinel.core.schemas import DecisionEnum, FindingStatus, Patch, Verification
from sentinel.remediation.engine import remediation_engine
from sentinel.remediation.patch_apply import sandbox_manager
from sentinel.verification.decider import decider
from sentinel.verification.regression_runner import security_regression_runner
from sentinel.verification.rescan import rescanner
from sentinel.verification.unit_runner import unit_test_runner


class VerificationEngine:
    """Manages the verification state machine and autonomous retry feedback loop."""

    def verify(
        self,
        patch_id: str,
        target_dir: Optional[Path] = None,
        auto_retry: bool = True,
        max_attempts: int = 3,
    ) -> Verification:
        """
        Executes end-to-end verification of a proposed patch on its dedicated sandbox branch.
        """
        patch: Optional[Patch] = db.get_patch(patch_id)
        if not patch:
            raise ValueError(f"Patch '{patch_id}' not found in database.")

        finding = db.get_finding(patch.finding_id)
        if not finding:
            raise ValueError(
                f"Finding '{patch.finding_id}' associated with patch '{patch_id}' not found."
            )

        # Determine sandbox location
        resolved_target = (
            Path(target_dir).resolve() if target_dir else Path("lab/sentinel-lab-app").resolve()
        )
        sandbox_path = sandbox_manager.sandbox_root / resolved_target.name
        if not sandbox_path.exists():
            # If sandbox does not exist yet, prepare it
            repo = sandbox_manager.prepare_sandbox(resolved_target)
        else:
            repo = git.Repo(sandbox_path)

        # Ensure active branch is the patch branch
        if patch.branch in [h.name for h in repo.heads]:
            repo.git.checkout(patch.branch, force=True)
        else:
            raise ValueError(
                f"Branch '{patch.branch}' for patch '{patch_id}' not found in sandbox."
            )

        audit_logger.log(
            event_type="VERIFICATION_STARTED",
            actor="VerificationEngine",
            details={
                "patch_id": patch.id,
                "finding_id": finding.id,
                "branch": patch.branch,
                "attempt": patch.attempt,
            },
        )

        # 1. Run Functional Unit Tests
        unit_passed, unit_log = unit_test_runner.run_tests(sandbox_path)

        # 2. Run Security Regression Checks
        reg_passed, reg_log = security_regression_runner.run_regression(finding, sandbox_path)

        # 3. Run Targeted Rescan
        orig_gone, new_findings, rescan_evidence = rescanner.rescan(finding, sandbox_path)

        # 4. Deterministic Decision Evaluation
        decision, reason = decider.decide(
            unit_passed=unit_passed,
            regression_passed=reg_passed,
            original_finding_gone=orig_gone,
            new_findings=new_findings,
        )

        evidence = {
            "unit_passed": unit_passed,
            "unit_log": unit_log,
            "regression_passed": reg_passed,
            "regression_log": reg_log,
            "original_finding_gone": orig_gone,
            "rescan_evidence": rescan_evidence,
            "decision_reason": reason,
        }

        verification = Verification(
            patch_id=patch.id,
            finding_id=finding.id,
            unit_passed=unit_passed,
            regression_passed=reg_passed,
            original_finding_gone=orig_gone,
            new_findings=new_findings,
            decision=decision,
            evidence=evidence,
            timestamp=datetime.now(timezone.utc),
        )

        # 5. Handle State Transition & Lifecycle Updates
        if decision == DecisionEnum.VERIFIED:
            db.update_finding_status(finding.id, FindingStatus.VERIFIED)
            db.save_verification(verification)
            audit_logger.log(
                event_type="PATCH_VERIFIED",
                actor="VerificationEngine",
                details={
                    "patch_id": patch.id,
                    "finding_id": finding.id,
                    "branch": patch.branch,
                    "reason": reason,
                },
            )
            return verification

        # If rejected:
        db.save_verification(verification)
        audit_logger.log(
            event_type="PATCH_REJECTED",
            actor="VerificationEngine",
            details={
                "patch_id": patch.id,
                "finding_id": finding.id,
                "decision": decision.value,
                "reason": reason,
            },
        )

        # Clean rollback of the rejected sandbox branch
        sandbox_manager.rollback_current_branch(repo)

        # 6. Autonomous Retry Feedback Loop
        if auto_retry and patch.attempt < max_attempts:
            next_attempt = patch.attempt + 1
            feedback = (
                f"Patch attempt {patch.attempt} was REJECTED by deterministic verifier.\n"
                f"Decision: {decision.value}\n"
                f"Reason: {reason}\n"
                f"Functional Test Output:\n{unit_log[:500]}\n"
                f"Security Regression Output:\n{reg_log[:500]}"
            )

            audit_logger.log(
                event_type="RETRY_SCHEDULED",
                actor="VerificationEngine",
                details={
                    "finding_id": finding.id,
                    "previous_patch": patch.id,
                    "next_attempt": next_attempt,
                },
            )

            # Propose next patch with feedback
            new_patch, new_repo = remediation_engine.remediate(
                finding=finding,
                target_dir=resolved_target,
                attempt=next_attempt,
                failure_feedback=feedback,
            )

            # Recursively verify the retry attempt
            return self.verify(
                patch_id=new_patch.id,
                target_dir=resolved_target,
                auto_retry=auto_retry,
                max_attempts=max_attempts,
            )

        # Max attempts exceeded
        db.update_finding_status(finding.id, FindingStatus.NEEDS_HUMAN)
        audit_logger.log(
            event_type="MAX_ATTEMPTS_EXCEEDED",
            actor="VerificationEngine",
            details={"finding_id": finding.id, "final_status": "NEEDS_HUMAN"},
        )
        return verification


verification_engine = VerificationEngine()
