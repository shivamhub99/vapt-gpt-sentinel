"""
sentinel/agents package initialization.
Exports Red, Blue, Judge, and Simulation orchestrator for digital twin game simulation.
"""

from sentinel.agents.blue import BlueAgent, blue_agent
from sentinel.agents.judge import JudgeAgent, judge_agent
from sentinel.agents.red import RedAgent, red_agent
from sentinel.agents.schemas import (
    BlueMove,
    RedMove,
    RoundResult,
    SimulationResult,
)
from sentinel.agents.simulation import (
    SimulationOrchestrator,
    simulation_orchestrator,
)

__all__ = [
    "BlueAgent",
    "BlueMove",
    "JudgeAgent",
    "RedAgent",
    "RedMove",
    "RoundResult",
    "SimulationOrchestrator",
    "SimulationResult",
    "blue_agent",
    "judge_agent",
    "red_agent",
    "simulation_orchestrator",
]
