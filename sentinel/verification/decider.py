"""
Deterministic Decision Engine for VAPT-GPT Sentinel Verification Loop.
Enforces the core rule:
- LLMs only propose patches.
- Deterministic checks decide whether to accept or rollback.
"""

from typing import List, Tuple

from sentinel.core.schemas import DecisionEnum, Finding


class VerificationDecider:
    """Evaluates multi-factor verification evidence to produce a deterministic decision."""

    def decide(
        self,
        unit_passed: bool,
        regression_passed: bool,
        original_finding_gone: bool,
        new_findings: List[Finding],
    ) -> Tuple[DecisionEnum, str]:
        """
        Determines the lifecycle verification state:
        VERIFIED: all functional tests pass, security invariants pass, finding eliminated, 0 new flaws.
        REJECTED_NEW_VULN: secondary vulnerability detected in rescan.
        REJECTED_UNRESOLVED: scanner confirmed original flaw still exists.
        REJECTED_FUNCTIONAL: unit or security functional regression tests failed.
        """
        if len(new_findings) > 0:
            flaws_str = ", ".join(f"{f.cwe} ({f.title})" for f in new_findings[:3])
            return (
                DecisionEnum.REJECTED_NEW_VULN,
                f"Patch introduced {len(new_findings)} new secondary vulnerabilities: {flaws_str}.",
            )

        if not original_finding_gone:
            return (
                DecisionEnum.REJECTED_UNRESOLVED,
                "Rescan confirmed the targeted vulnerability is still actively present in the source.",
            )

        if not unit_passed:
            return (
                DecisionEnum.REJECTED_FUNCTIONAL,
                "Functional unit tests broke after patch application. Legitimate functionality impaired.",
            )

        if not regression_passed:
            return (
                DecisionEnum.REJECTED_FUNCTIONAL,
                "Security invariant assertion failed. Defensive coding standards not satisfied.",
            )

        return (
            DecisionEnum.VERIFIED,
            "Patch verified: functional unit tests passed, security invariants satisfied, "
            "vulnerability eliminated, and zero secondary flaws detected.",
        )


decider = VerificationDecider()
