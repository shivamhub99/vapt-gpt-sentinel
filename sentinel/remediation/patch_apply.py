"""
Sandbox and Git Branch Patch Application Engine for VAPT-GPT Sentinel.
Enforces Hard Safety Rule 4:
- Patches are applied strictly to a sandbox clone on a dedicated Git branch.
- Never modifies the original primary target worktree directly.
- Handles clean rollbacks on conflicts or test failures.
"""

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import git

from sentinel.core.audit_log import audit_logger
from sentinel.core.settings import settings


class SandboxError(Exception):
    """Raised when sandbox operations or git branch actions fail."""


class PatchApplicationError(Exception):
    """Raised when applying a unified diff encounters conflicts or syntax errors."""


class SandboxManager:
    """
    Manages isolated repository sandboxes and Git feature branches for safe patch testing.
    """

    def __init__(self, sandbox_root: Optional[Path] = None):
        self.sandbox_root = sandbox_root or (settings.runs_dir.parent / ".sentinel" / "sandbox")
        self.sandbox_root.mkdir(parents=True, exist_ok=True)

    def prepare_sandbox(self, target_repo_path: Path) -> git.Repo:
        """
        Creates or updates an isolated sandbox copy of the target repository.
        """
        target_path = Path(target_repo_path).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target repository path does not exist: {target_path}")

        repo_name = target_path.name
        sandbox_path = self.sandbox_root / repo_name

        if sandbox_path.exists():
            try:
                repo = git.Repo(sandbox_path)
                # Ensure clean working tree on main/master
                default_branch = (
                    "main"
                    if "main" in repo.heads
                    else ("master" if "master" in repo.heads else None)
                )
                if default_branch:
                    repo.git.checkout(default_branch, force=True)
                repo.git.clean("-fd")
                return repo
            except Exception:
                # Corrupted sandbox, remove and re-clone
                shutil.rmtree(sandbox_path, ignore_errors=True)

        # Clone target repository into sandbox
        try:
            repo = git.Repo.clone_from(str(target_path), str(sandbox_path))
            return repo
        except Exception:
            # If target is not a full git repo, initialize git in sandbox
            sandbox_path.mkdir(parents=True, exist_ok=True)
            for item in target_path.glob("*"):
                if item.name not in (".git", ".venv", "__pycache__"):
                    if item.is_dir():
                        shutil.copytree(item, sandbox_path / item.name, dirs_exist_ok=True)
                    else:
                        shutil.copy2(item, sandbox_path / item.name)

            repo = git.Repo.init(sandbox_path)
            repo.git.add(all=True)
            repo.index.commit("Initial sandbox state")
            return repo

    def create_fix_branch(self, repo: git.Repo, finding_id: str, attempt: int = 1) -> str:
        """
        Creates and checks out a new isolated branch for this remediation attempt.
        Format: sentinel/fix-<clean_finding_id>-<attempt>
        """
        clean_id = finding_id.replace("_", "-").replace(":", "-").lower()
        branch_name = f"sentinel/fix-{clean_id}-att{attempt}"

        # Ensure base branch is active
        default_branch = (
            "main"
            if "main" in repo.heads
            else ("master" if "master" in repo.heads else repo.active_branch.name)
        )
        repo.git.checkout(default_branch, force=True)
        repo.git.clean("-fd")

        # Delete branch if it already exists from earlier aborted runs
        if branch_name in [h.name for h in repo.heads]:
            repo.delete_head(branch_name, force=True)

        new_branch = repo.create_head(branch_name)
        new_branch.checkout()

        audit_logger.log(
            event_type="BRANCH_CREATED",
            actor="SandboxManager",
            details={"branch": branch_name, "finding_id": finding_id, "attempt": attempt},
        )
        return branch_name

    def apply_diff(
        self,
        repo: git.Repo,
        diff_text: str,
        finding_id: str,
        rationale: str = "",
    ) -> bool:
        """
        Validates and applies a unified diff onto the active sandbox branch.
        Reverts cleanly on conflict.
        """
        sandbox_path = Path(repo.working_dir)
        temp_patch_file = sandbox_path / ".sentinel_patch.tmp"

        # Normalize line endings to raw LF bytes (prevents Windows CRLF corruption in git apply)
        normalized_diff = diff_text.replace("\r\n", "\n")
        if not normalized_diff.endswith("\n"):
            normalized_diff += "\n"

        temp_patch_file.write_bytes(normalized_diff.encode("utf-8"))

        try:
            # Check if patch applies cleanly
            repo.git.apply("--check", "--unidiff-zero", str(temp_patch_file))
            # Apply patch
            repo.git.apply("--whitespace=fix", "--unidiff-zero", str(temp_patch_file))

            # Stage and commit
            repo.git.add(all=True)
            commit_msg = (
                f"fix(security): remediate {finding_id}\n\n"
                f"Rationale: {rationale}\n"
                f"Timestamp: {datetime.now(timezone.utc).isoformat()}"
            )
            repo.index.commit(commit_msg)

            audit_logger.log(
                event_type="PATCH_APPLIED",
                actor="SandboxManager",
                details={
                    "finding_id": finding_id,
                    "branch": repo.active_branch.name,
                    "rationale": rationale,
                },
            )
            return True
        except git.GitCommandError as exc:
            # Revert any partial changes cleanly
            self.rollback_current_branch(repo)
            audit_logger.log(
                event_type="PATCH_APPLY_FAILED",
                actor="SandboxManager",
                details={"finding_id": finding_id, "error": str(exc)},
            )
            raise PatchApplicationError(
                f"Failed to apply patch for {finding_id}: {exc.stderr}"
            ) from exc
        finally:
            if temp_patch_file.exists():
                try:
                    temp_patch_file.unlink()
                except Exception:
                    pass

    def rollback_current_branch(self, repo: git.Repo) -> None:
        """
        Reverts uncommitted and committed changes on the active sandbox branch.
        """
        try:
            repo.git.checkout(force=True)
            repo.git.clean("-fd")
            default_branch = (
                "main" if "main" in repo.heads else ("master" if "master" in repo.heads else None)
            )
            if default_branch:
                repo.git.checkout(default_branch, force=True)
            audit_logger.log(
                event_type="SANDBOX_ROLLED_BACK",
                actor="SandboxManager",
                details={"repo": str(repo.working_dir)},
            )
        except Exception:
            pass


sandbox_manager = SandboxManager()
