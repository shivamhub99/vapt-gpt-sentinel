"""
Core Pydantic v2 Data Models and Schemas for VAPT-GPT Sentinel.
Defines canonical schemas for Findings, Risk Scores, Patches, Verifications, and Digital Twin Nodes.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    PATCH_IN_PROGRESS = "PATCH_IN_PROGRESS"
    VERIFIED = "VERIFIED"
    SUPPRESSED = "SUPPRESSED"
    ROLLBACK = "ROLLBACK"
    NEEDS_HUMAN = "NEEDS_HUMAN"


class DecisionEnum(str, Enum):
    VERIFIED = "VERIFIED"
    REJECTED_NEW_VULN = "REJECTED_NEW_VULN"
    REJECTED_FUNCTIONAL = "REJECTED_FUNCTIONAL"
    REJECTED_UNRESOLVED = "REJECTED_UNRESOLVED"
    NEEDS_HUMAN = "NEEDS_HUMAN"


class Finding(BaseModel):
    """
    Canonical security finding representation aggregated across all scanning tools.
    """

    id: str = Field(description="Unique finding identifier (e.g. finding_sqli_app_145)")
    tool: str = Field(
        description="Scanner or comma-separated list of scanners that detected this issue"
    )
    cwe: str = Field(default="CWE-Unknown", description="Canonical CWE identifier (e.g. CWE-89)")
    owasp: Optional[str] = Field(
        default=None, description="OWASP Top 10 category (e.g. A03:2021-Injection)"
    )
    title: str = Field(description="Descriptive summary of the vulnerability")
    severity: Severity = Field(default=Severity.MEDIUM, description="Normalized severity rating")
    cvss: Optional[float] = Field(
        default=None, ge=0.0, le=10.0, description="CVSS v3.1 base score if known"
    )
    epss: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="EPSS exploit prediction probability"
    )
    file: Optional[str] = Field(default=None, description="Relative or absolute file path")
    line: Optional[int] = Field(
        default=None, description="Line number of vulnerable code statement"
    )
    endpoint: Optional[str] = Field(default=None, description="HTTP endpoint or URL if web-facing")
    param: Optional[str] = Field(
        default=None, description="Vulnerable HTTP parameter or variable name"
    )
    evidence: str = Field(
        default="", description="Code snippet, scanner evidence, or banner string"
    )
    status: FindingStatus = Field(
        default=FindingStatus.OPEN, description="Current remediation state"
    )
    contextual_score: Optional[float] = Field(
        default=None, ge=0.0, le=100.0, description="Calculated multi-factor contextual risk score"
    )
    threat_context: Optional[str] = Field(
        default=None, description="LLM qualitative threat rationale and exposure narrative"
    )
    description: Optional[str] = Field(
        default=None, description="Detailed vulnerability description"
    )
    exploitability: Optional[str] = Field(
        default=None, description="Attack surface exposure details"
    )
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when finding was first discovered",
    )
    raw_tool_data: Dict[str, Any] = Field(
        default_factory=dict, description="Original raw scanner output payload"
    )


class ContextFactors(BaseModel):
    """Contextual exposure factors determining operational threat level."""

    internet_facing: bool = False
    data_sensitivity: str = "public"  # public, internal, confidential, restricted
    reachability: bool = True
    auth_required: bool = False
    graph_centrality: float = 0.0


class RiskScore(BaseModel):
    """Contextual risk prioritization score for a finding."""

    finding_id: str
    base_score: float = Field(ge=0.0, le=10.0, description="Baseline CVSS or tool score")
    context_factors: ContextFactors
    final_score: float = Field(
        ge=0.0, le=100.0, description="Normalized 0-100 contextual risk score"
    )
    explanation: str = Field(default="", description="Detailed rationale of computed risk")


class Patch(BaseModel):
    """Proposed source code patch for a finding."""

    id: str = Field(description="Unique patch identifier (e.g. patch_sqli_attempt_1)")
    finding_id: str
    diff: str = Field(description="Unified diff representing changes")
    branch: str = Field(description="Git branch name where patch was applied in sandbox")
    rationale: str = Field(description="Explanation of how the patch fixes the issue")
    attempt: int = Field(default=1, ge=1, le=5, description="Attempt number (max 3-5)")
    generated_by: str = Field(
        default="template", description="Engine that generated patch (template or llm)"
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Verification(BaseModel):
    """Deterministic verification result evaluating a proposed patch."""

    patch_id: str
    finding_id: str
    unit_passed: bool = Field(description="Whether functional regression tests passed")
    regression_passed: bool = Field(
        description="Whether specific security regression assertions passed"
    )
    original_finding_gone: bool = Field(
        description="Whether re-scan confirmed the vulnerability is gone"
    )
    new_findings: List[Finding] = Field(
        default_factory=list, description="Any new vulnerabilities introduced"
    )
    decision: DecisionEnum = Field(description="Final decision state")
    evidence: Dict[str, Any] = Field(
        default_factory=dict, description="Test output logs and rescan diffs"
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
