"""
Functional Unit Test Runner for VAPT-GPT Sentinel Verification Loop.
Executes test suites (e.g. pytest) against the sandboxed patched repository to
verify that code changes have not broken existing legitimate functionality.
"""

import subprocess
import sys
from pathlib import Path
from typing import Tuple


class UnitTestRunner:
    """Executes existing project unit/functional tests against the sandbox workspace."""

    def __init__(self, timeout_seconds: int = 60):
        self.timeout_seconds = timeout_seconds

    def find_test_directory(self, sandbox_dir: Path) -> Path | None:
        """Discovers the primary test directory in the sandbox repository."""
        candidates = [
            sandbox_dir / "tests",
            sandbox_dir / "test",
            sandbox_dir / "lab" / "sentinel-lab-app" / "tests",
        ]
        for candidate in candidates:
            if candidate.exists() and candidate.is_dir():
                return candidate
        return None

    def run_tests(self, sandbox_dir: Path) -> Tuple[bool, str]:
        """
        Executes pytest in the sandbox environment.
        Returns Tuple of (tests_passed: bool, diagnostic_output: str).
        """
        test_dir = self.find_test_directory(sandbox_dir)
        if not test_dir:
            return (
                True,
                "No functional test suite found in sandbox; skipping unit test verification.",
            )

        python_exe = sys.executable
        cmd = [
            python_exe,
            "-m",
            "pytest",
            "-v",
            "--import-mode=importlib",
            str(test_dir),
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(sandbox_dir),
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )

            passed = result.returncode == 0
            output = result.stdout or result.stderr
            if passed:
                return True, "All functional unit tests passed successfully.\n" + output[-500:]

            # Extract failure snippet for LLM feedback
            failure_lines = []
            for line in output.splitlines():
                if "FAILED" in line or "ERROR" in line or "assert " in line or "Traceback" in line:
                    failure_lines.append(line)
            failure_summary = "\n".join(failure_lines[:25]) or output[-1000:]
            return (
                False,
                f"Functional test failure (exit code {result.returncode}):\n{failure_summary}",
            )

        except subprocess.TimeoutExpired:
            return False, f"Unit test execution timed out after {self.timeout_seconds} seconds."
        except Exception as exc:
            return False, f"Error launching unit test suite: {str(exc)}"


unit_test_runner = UnitTestRunner()
