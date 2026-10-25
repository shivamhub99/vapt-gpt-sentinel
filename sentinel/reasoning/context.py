"""
Application Context Engine for VAPT-GPT Sentinel.
Attaches real-world operational exposure, asset criticality, data classification,
and reachability context from config/app_context.yaml to each finding.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from sentinel.core.schemas import ContextFactors, Finding
from sentinel.core.settings import settings


class AppContextEngine:
    """Ingests application context and computes environmental exposure factors."""

    def __init__(self, context_file: Optional[Path] = None):
        self.context_file = context_file or settings.app_context_path
        self.context_data: Dict[str, Any] = self._load_context()

    def _load_context(self) -> Dict[str, Any]:
        if not self.context_file.exists():
            return {"application": {"internet_facing": True, "endpoints": []}}
        try:
            with open(self.context_file, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {"application": {"internet_facing": True, "endpoints": []}}

    def enrich_finding(self, finding: Finding) -> ContextFactors:
        """
        Determines contextual exposure factors for a given finding based on its
        endpoint, file location, or vulnerability type.
        """
        app_cfg = self.context_data.get("application", {})
        default_internet = app_cfg.get("internet_facing", True)
        endpoints: List[Dict[str, Any]] = app_cfg.get("endpoints", [])

        # Default factors
        internet_facing = default_internet
        data_sensitivity = "internal"
        auth_required = False
        reachability = True
        graph_centrality = 0.1

        # 1. Match by endpoint URL if finding is web-facing
        if finding.endpoint:
            matched_endpoint = None
            for ep in endpoints:
                ep_path = ep.get("path", "")
                if ep_path and ep_path in finding.endpoint:
                    matched_endpoint = ep
                    break

            if matched_endpoint:
                auth_required = matched_endpoint.get("auth_required", False)
                data_sensitivity = matched_endpoint.get("data_sensitivity", "public")
                internet_facing = True
                reachability = True

        # 2. Match by file or vulnerability category
        if finding.cwe == "CWE-89":
            # SQL Injection directly threatens the database crown-jewel
            data_sensitivity = "restricted"
            graph_centrality = 0.8
        elif finding.cwe == "CWE-798":
            # Hardcoded API Secret threatens entire service auth
            data_sensitivity = "restricted"
            graph_centrality = 0.9
        elif finding.cwe == "CWE-639":
            # IDOR exposes confidential customer orders
            data_sensitivity = "confidential"
            auth_required = True
            graph_centrality = 0.5
        elif finding.cwe == "CWE-1395":
            # Pinned dependency (Werkzeug / requests)
            data_sensitivity = "internal"
            graph_centrality = 0.4
        elif finding.cwe in ("CWE-693", "CWE-16", "CWE-942"):
            # Headers and CORS misconfigurations
            data_sensitivity = "public"
            graph_centrality = 0.2

        return ContextFactors(
            internet_facing=internet_facing,
            data_sensitivity=data_sensitivity,
            reachability=reachability,
            auth_required=auth_required,
            graph_centrality=graph_centrality,
        )


context_engine = AppContextEngine()
