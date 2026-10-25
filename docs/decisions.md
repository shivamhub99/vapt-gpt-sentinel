# Architecture Decision Records (ADRs)

## ADR-001: Closed-Loop Architecture: LLM Proposes, Deterministic Checks Decide
* **Date**: 2026-10-25
* **Status**: Accepted
* **Context**: LLMs exhibit stochastic generation and hallucination. Allowing an LLM to evaluate its own patches introduces unconstrained self-confirmation bias.
* **Decision**: All critical gates (unit tests, security regression tests, rescan diffs) are strictly deterministic Python test harnesses. The LLM only proposes candidate unified diffs and explanations.

## ADR-002: Dual Boundary Scope Protection
* **Date**: 2026-10-25
* **Status**: Accepted
* **Context**: Running security scanners without authorization poses legal and ethical violations.
* **Decision**: Every scanner execution is guarded by `ScopeGuard` verifying target IPs/hostnames against `config/scope.yaml` and asserting `SENTINEL_I_OWN_THIS_TARGET=true` in `.env`. Out-of-scope targets trigger immediate termination and append an immutable event to `runs/audit_log.jsonl`.

## ADR-003: Isolated Git Sandbox Branches for Remediation
* **Date**: 2026-10-25
* **Status**: Accepted
* **Context**: In-place edits to production or test files risk permanent data loss or irrecoverable code states.
* **Decision**: Patches are applied strictly on dedicated Git sandbox branches (`sentinel/fix-<finding_id>-<attempt>`). If tests fail, the branch is rolled back.

## ADR-004: In-Memory Attack Graph Modeling (Zero Network Traffic)
* **Date**: 2026-10-25
* **Status**: Accepted
* **Context**: Red/Blue simulation agents must never generate live network attacks or weaponized exploits.
* **Decision**: The Red and Blue agents operate exclusively as graph traversers on an in-memory NetworkX digital twin. All metrics are calculated by deterministic path probability formulas.
