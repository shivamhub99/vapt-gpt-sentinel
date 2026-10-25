# Framework Limitations & Remediation Boundaries

This document enumerates intentional design constraints and boundaries where automated remediation is purposefully restricted.

## 1. Categories Requiring Mandatory Human Approval (NEEDS_HUMAN)
The following vulnerability categories cannot be auto-merged by VAPT-GPT Sentinel:
- **Authentication Bypass & Credential Verification (CWE-287)**: Modifying login or session verification algorithms carries high false-positive business risk.
- **Access Control & Authorization Logic (CWE-284, CWE-639 / IDOR)**: Determining business-level ownership rules requires contextual architectural knowledge that cannot be reliably inferred automatically without regression risk.
- **Financial & Payment Processing Logic**: Any codebase region touching transactions, billing, or ledger operations is strictly gated by human sign-off.
- **Cryptographic Primitive Selection (CWE-327)**: Key rotation and cipher upgrades require operational planning.

## 2. Scanner Constraints
- Scanners run exclusively in baseline / non-destructive modes.
- Active exploitation frameworks (e.g., Metasploit, automated SQLMap with `--os-shell`) are explicitly prohibited.
- DoS testing and buffer overflow fuzzing are excluded from scope.

## 3. Environment Isolation
- Verification requires local containerized execution or local test runners. Remote third-party production systems cannot be directly remediated.
