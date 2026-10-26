"""
Digital Twin Knowledge Graph Topology for VAPT-GPT Sentinel (RQ2, RQ3).
Uses NetworkX directed graphs to model assets, vulnerabilities, reachability,
and exploit relationships across the target environment.
"""

from enum import Enum
from typing import Any, Dict, List, Optional

import networkx as nx
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    ENTRY = "ENTRY"
    SERVICE = "SERVICE"
    ENDPOINT = "ENDPOINT"
    DATASTORE = "DATASTORE"
    ACCOUNT = "ACCOUNT"
    SECRET = "SECRET"  # noqa: S105
    FINDING = "FINDING"


class EdgeType(str, Enum):
    REACHES = "REACHES"
    EXPLOITS = "EXPLOITS"
    ACCESSES = "ACCESSES"
    READS = "READS"
    AUTHENTICATES = "AUTHENTICATES"
    ESCALATES = "ESCALATES"
    COMPROMISES = "COMPROMISES"


class TwinNode(BaseModel):
    id: str
    label: str
    node_type: NodeType
    criticality: float = Field(default=0.5, ge=0.0, le=1.0)
    is_entry_point: bool = False
    is_crown_jewel: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TwinEdge(BaseModel):
    source: str
    target: str
    edge_type: EdgeType
    probability: float = Field(default=0.5, ge=0.0, le=1.0)
    cost: float = Field(default=1.0, ge=0.1, le=100.0)
    finding_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DigitalTwinGraph:
    """Directed graph representing system assets, threat entryways, and exploit linkages."""

    def __init__(self, name: str = "sentinel_twin"):
        self.name = name
        self.graph = nx.DiGraph()

    def add_node(self, node: TwinNode) -> None:
        """Adds a typed asset or finding node to the digital twin."""
        self.graph.add_node(
            node.id,
            label=node.label,
            node_type=node.node_type.value,
            criticality=node.criticality,
            is_entry_point=node.is_entry_point,
            is_crown_jewel=node.is_crown_jewel,
            metadata=node.metadata,
        )

    def add_edge(self, edge: TwinEdge) -> None:
        """Adds a directional reachability or exploit edge."""
        self.graph.add_edge(
            edge.source,
            edge.target,
            edge_type=edge.edge_type.value,
            probability=edge.probability,
            cost=edge.cost,
            finding_id=edge.finding_id,
            metadata=edge.metadata,
        )

    def get_entry_nodes(self) -> List[str]:
        """Returns node IDs where adversaries can enter the system (e.g. Internet)."""
        return [n for n, data in self.graph.nodes(data=True) if data.get("is_entry_point", False)]

    def get_crown_jewels(self) -> List[str]:
        """Returns critical high-impact target node IDs (e.g. Databases, Admin accounts)."""
        return [n for n, data in self.graph.nodes(data=True) if data.get("is_crown_jewel", False)]

    def clone(self) -> "DigitalTwinGraph":
        """Creates an in-memory deep clone for counterfactual simulations."""
        cloned = DigitalTwinGraph(name=f"{self.name}_clone")
        cloned.graph = self.graph.copy()
        return cloned

    def to_dict(self) -> Dict[str, Any]:
        """Serializes digital twin graph topology for JSON export and UI rendering."""
        nodes = []
        for n, data in self.graph.nodes(data=True):
            nodes.append({"id": n, **data})

        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append({"source": u, "target": v, **data})

        return {
            "name": self.name,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
        }

    def to_mermaid(self) -> str:
        """Generates a Mermaid.js flowchart string for visual artifact inspection."""
        lines = ["flowchart LR"]
        type_styles = {
            NodeType.ENTRY.value: "style {id} fill:#ef4444,stroke:#b91c1c,color:#fff",
            NodeType.DATASTORE.value: "style {id} fill:#8b5cf6,stroke:#6d28d9,color:#fff",
            NodeType.ACCOUNT.value: "style {id} fill:#f59e0b,stroke:#d97706,color:#fff",
            NodeType.FINDING.value: "style {id} fill:#ec4899,stroke:#be185d,color:#fff",
            NodeType.SERVICE.value: "style {id} fill:#3b82f6,stroke:#1d4ed8,color:#fff",
        }

        # Add nodes
        for n, data in self.graph.nodes(data=True):
            label = data.get("label", n)
            lines.append(f'    {n}["{label}"]')

        # Add edges
        for u, v, data in self.graph.edges(data=True):
            prob = data.get("probability", 1.0)
            etype = data.get("edge_type", "reaches")
            lines.append(f'    {u} -->|"{etype} (P={prob:.2f})"| {v}')

        # Add styles
        for n, data in self.graph.nodes(data=True):
            ntype = data.get("node_type")
            if ntype in type_styles:
                lines.append("    " + type_styles[ntype].format(id=n))

        return "\n".join(lines)
