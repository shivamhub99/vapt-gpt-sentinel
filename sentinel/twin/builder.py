"""
Digital Twin Graph Builder for VAPT-GPT Sentinel (RQ2, RQ3).
Synthesizes application context, critical assets, network exposure, and security
findings into a unified NetworkX directed attack-surface graph.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from sentinel.core.schemas import Finding
from sentinel.core.settings import settings
from sentinel.intel.epss import epss_lookup
from sentinel.twin.graph import (
    DigitalTwinGraph,
    EdgeType,
    NodeType,
    TwinEdge,
    TwinNode,
)


class TwinBuilder:
    """Constructs a DigitalTwinGraph from contextual configurations and security findings."""

    def __init__(self, context_path: Optional[Path] = None):
        self.context_path = context_path or settings.app_context_path

    def _load_context(self) -> Dict[str, Any]:
        """Loads application architecture and asset definitions from YAML."""
        if not self.context_path.exists():
            return {}
        try:
            with open(self.context_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def build(self, findings: Optional[List[Finding]] = None) -> DigitalTwinGraph:
        """
        Builds the complete digital twin graph by linking threat entryways,
        application tiers, assets, and vulnerability exploit edges.
        """
        context = self._load_context()
        twin = DigitalTwinGraph(name="sentinel_lab_app_twin")

        # 1. Threat Entry Point: Internet / External Adversary
        twin.add_node(
            TwinNode(
                id="internet",
                label="Internet (Adversary)",
                node_type=NodeType.ENTRY,
                criticality=0.0,
                is_entry_point=True,
                is_crown_jewel=False,
            )
        )

        # 2. Web Application Service Node
        twin.add_node(
            TwinNode(
                id="web_app",
                label="Flask Web Application",
                node_type=NodeType.SERVICE,
                criticality=0.6,
                is_entry_point=False,
                is_crown_jewel=False,
            )
        )
        twin.add_edge(
            TwinEdge(
                source="internet",
                target="web_app",
                edge_type=EdgeType.REACHES,
                probability=1.0,
                cost=1.0,
            )
        )

        # 3. Endpoints from context
        endpoints = context.get("application", {}).get("endpoints", [])
        if not endpoints:
            # Fallback default lab endpoints
            endpoints = [
                {"path": "/api/search", "auth_required": False, "data_sensitivity": "public"},
                {"path": "/api/greet", "auth_required": False, "data_sensitivity": "public"},
                {"path": "/api/orders", "auth_required": True, "data_sensitivity": "confidential"},
                {
                    "path": "/api/orders/<id>",
                    "auth_required": True,
                    "data_sensitivity": "confidential",
                },
                {
                    "path": "/api/validate-key",
                    "auth_required": True,
                    "data_sensitivity": "restricted",
                },
            ]

        for ep in endpoints:
            path = ep.get("path", "")
            node_id = (
                f"endpoint_{path.replace('/', '_').replace('<', '').replace('>', '').strip('_')}"
            )
            twin.add_node(
                TwinNode(
                    id=node_id,
                    label=f"Endpoint: {path}",
                    node_type=NodeType.ENDPOINT,
                    criticality=0.5 if ep.get("auth_required") else 0.4,
                    metadata=ep,
                )
            )
            twin.add_edge(
                TwinEdge(
                    source="web_app",
                    target=node_id,
                    edge_type=EdgeType.REACHES,
                    probability=1.0,
                    cost=1.0,
                )
            )

        # 4. Critical Crown Jewel Assets
        twin.add_node(
            TwinNode(
                id="database",
                label="SQLite Database (lab.db)",
                node_type=NodeType.DATASTORE,
                criticality=0.95,
                is_crown_jewel=True,
            )
        )
        twin.add_node(
            TwinNode(
                id="orders_ledger",
                label="Customer Orders Ledger",
                node_type=NodeType.DATASTORE,
                criticality=0.85,
                is_crown_jewel=True,
            )
        )
        twin.add_node(
            TwinNode(
                id="admin_account",
                label="Administrator Account",
                node_type=NodeType.ACCOUNT,
                criticality=1.0,
                is_crown_jewel=True,
            )
        )
        twin.add_node(
            TwinNode(
                id="api_secret_key",
                label="API Secret Key",
                node_type=NodeType.SECRET,
                criticality=0.8,
            )
        )

        # 5. Connect Findings as Exploit Linkages
        for finding in findings or []:
            cwe = finding.cwe.upper()

            # Probability calculation grounded in EPSS and CVSS
            base_epss = finding.epss or epss_lookup.get_epss_score(finding.cwe)
            cvss_prob = (finding.cvss or 5.0) / 10.0
            exploit_prob = min(0.99, max(0.15, (0.5 * cvss_prob) + (0.5 * base_epss) + 0.3))

            finding_node_id = f"finding_{finding.id.replace(':', '_').lower()}"
            twin.add_node(
                TwinNode(
                    id=finding_node_id,
                    label=f"{finding.cwe}: {finding.title[:35]}",
                    node_type=NodeType.FINDING,
                    criticality=cvss_prob,
                    metadata={"finding_id": finding.id, "cwe": finding.cwe, "cvss": finding.cvss},
                )
            )

            # Map specific findings to assets
            if cwe == "CWE-89" or "sql" in finding.title.lower():
                # SQLi links /api/search -> finding -> database
                twin.add_edge(
                    TwinEdge(
                        source="endpoint_api_search",
                        target=finding_node_id,
                        edge_type=EdgeType.EXPLOITS,
                        probability=exploit_prob,
                        cost=2.0,
                        finding_id=finding.id,
                    )
                )
                twin.add_edge(
                    TwinEdge(
                        source=finding_node_id,
                        target="database",
                        edge_type=EdgeType.READS,
                        probability=0.95,
                        cost=1.0,
                        finding_id=finding.id,
                    )
                )

            elif cwe == "CWE-639" or "idor" in finding.title.lower():
                # IDOR links /api/orders/<id> -> finding -> orders_ledger
                twin.add_edge(
                    TwinEdge(
                        source="endpoint_api_orders_id",
                        target=finding_node_id,
                        edge_type=EdgeType.EXPLOITS,
                        probability=exploit_prob,
                        cost=1.5,
                        finding_id=finding.id,
                    )
                )
                twin.add_edge(
                    TwinEdge(
                        source=finding_node_id,
                        target="orders_ledger",
                        edge_type=EdgeType.READS,
                        probability=0.90,
                        cost=1.0,
                        finding_id=finding.id,
                    )
                )

            elif (
                cwe == "CWE-798"
                or "secret" in finding.title.lower()
                or "key" in finding.title.lower()
            ):
                # Hardcoded secret links web_app -> finding -> api_secret_key -> admin_account
                twin.add_edge(
                    TwinEdge(
                        source="web_app",
                        target=finding_node_id,
                        edge_type=EdgeType.EXPLOITS,
                        probability=exploit_prob,
                        cost=1.0,
                        finding_id=finding.id,
                    )
                )
                twin.add_edge(
                    TwinEdge(
                        source=finding_node_id,
                        target="api_secret_key",
                        edge_type=EdgeType.ACCESSES,
                        probability=0.95,
                        cost=1.0,
                        finding_id=finding.id,
                    )
                )
                twin.add_edge(
                    TwinEdge(
                        source="api_secret_key",
                        target="admin_account",
                        edge_type=EdgeType.AUTHENTICATES,
                        probability=0.90,
                        cost=1.0,
                    )
                )

            elif (
                cwe in ("CWE-693", "CWE-942", "CWE-614")
                or "header" in finding.title.lower()
                or "cors" in finding.title.lower()
            ):
                # Missing headers / wildcard CORS allows cross-origin escalation
                twin.add_edge(
                    TwinEdge(
                        source="internet",
                        target=finding_node_id,
                        edge_type=EdgeType.EXPLOITS,
                        probability=exploit_prob,
                        cost=1.0,
                        finding_id=finding.id,
                    )
                )
                twin.add_edge(
                    TwinEdge(
                        source=finding_node_id,
                        target="web_app",
                        edge_type=EdgeType.COMPROMISES,
                        probability=0.60,
                        cost=2.0,
                        finding_id=finding.id,
                    )
                )

            else:
                # Generic finding linkage to web application
                twin.add_edge(
                    TwinEdge(
                        source="web_app",
                        target=finding_node_id,
                        edge_type=EdgeType.EXPLOITS,
                        probability=exploit_prob,
                        cost=3.0,
                        finding_id=finding.id,
                    )
                )

        return twin


twin_builder = TwinBuilder()
