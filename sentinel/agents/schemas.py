"""
Data Models for Multi-Agent Digital Twin Simulation (Phase 7).
Defines schemas for Red moves, Blue responses, Judge rounds, and simulation summaries.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class RedMove(BaseModel):
    """Adversarial action selected by the Red agent on the digital twin graph."""

    path_id: str
    targeted_crown_jewel: str
    target_criticality: float = Field(ge=0.0, le=1.0)
    path_probability: float = Field(ge=0.0, le=1.0)
    attacker_cost: float = Field(ge=0.0)
    attack_utility: float = Field(ge=0.0)
    exploited_finding: Optional[str] = None
    narrative: str = ""


class BlueMove(BaseModel):
    """Defensive countermeasure proposed by the Blue agent to neutralize or attenuate threat paths."""

    action_type: str  # PATCH_FINDING, REQUIRE_AUTH, ADD_WAF, ISOLATE_NODE
    target: str
    target_label: str
    operational_cost: float = Field(ge=0.0)
    rationale: str = ""


class RoundResult(BaseModel):
    """Outcome of a single turn-based simulation round arbitrated by the Judge."""

    round_number: int
    red_move: Optional[RedMove] = None
    blue_move: Optional[BlueMove] = None
    pre_round_risk: float = Field(ge=0.0, le=100.0)
    post_round_risk: float = Field(ge=0.0, le=100.0)
    risk_delta: float
    paths_remaining: int
    path_displaced: bool = False
    displaced_to: Optional[str] = None
    judge_narrative: str = ""


class SimulationResult(BaseModel):
    """Complete summary of the turn-based multi-agent digital twin simulation."""

    simulation_id: str
    seed: int
    max_rounds: int
    initial_risk_score: float = Field(ge=0.0, le=100.0)
    final_risk_score: float = Field(ge=0.0, le=100.0)
    total_risk_reduction_pct: float
    total_blue_cost: float
    rounds: List[RoundResult] = Field(default_factory=list)
    converged: bool = False
    winner: str  # BLUE, RED, DRAW
    stop_reason: str = ""
    executive_summary: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
