"""
Digital Twin and Attack Path Simulation Package for VAPT-GPT Sentinel (RQ2, RQ3).
"""

from sentinel.twin.attack_paths import AttackPath, AttackPathAnalyzer, attack_path_analyzer
from sentinel.twin.builder import TwinBuilder, twin_builder
from sentinel.twin.counterfactual import (
    CounterfactualEngine,
    CounterfactualResult,
    Intervention,
    counterfactual_engine,
)
from sentinel.twin.graph import (
    DigitalTwinGraph,
    EdgeType,
    NodeType,
    TwinEdge,
    TwinNode,
)
from sentinel.twin.risk import SystemRiskCalculator, system_risk_calculator

__all__ = [
    "DigitalTwinGraph",
    "NodeType",
    "EdgeType",
    "TwinNode",
    "TwinEdge",
    "TwinBuilder",
    "twin_builder",
    "AttackPath",
    "AttackPathAnalyzer",
    "attack_path_analyzer",
    "SystemRiskCalculator",
    "system_risk_calculator",
    "Intervention",
    "CounterfactualResult",
    "CounterfactualEngine",
    "counterfactual_engine",
]
