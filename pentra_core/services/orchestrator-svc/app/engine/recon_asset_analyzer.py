"""Recon asset analyzer — classifies discovered assets for recon planning.

MOD-10: Inspects attack graph nodes and classifies them by recon-relevant
asset type, enabling the recon planner to match appropriate actions.

Asset classifications:
  - subdomain       — discovered subdomain
  - web_service     — HTTP/HTTPS service
  - network_service — non-web network service (SSH, FTP, SMB, etc.)
  - api_endpoint    — API-related endpoint
  - cloud_asset     — cloud infrastructure asset
  - web_endpoint    — generic web endpoint
"""

from __future__ import annotations

__classification__ = "runtime_optional"

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.attack_graph_builder import AttackGraph, AttackNode

logger = logging.getLogger(__name__)


@dataclass
class ReconAsset:
    """A classified asset ready for recon planning."""

    node_id: str
    label: str
    asset_class: str        # subdomain | web_service | network_service | api_endpoint | cloud_asset | web_endpoint
    node_type: str           # original graph node type
    properties: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "label": self.label,
            "asset_class": self.asset_class,
            "node_type": self.node_type,
        }


# ── Classification rules ────────────────────────────────────────────

_WEB_INDICATORS = {"http", "https", "443", "80", "8080", "8443", "web"}
_CLOUD_INDICATORS = {"aws", "s3", "azure", "gcp", "cloud", "bucket", "lambda", "ec2"}
_API_INDICATORS = {"api", "/v1", "/v2", "/v3", "graphql", "json", "rest", "swagger"}
_NETWORK_SERVICES = {"ssh", "ftp", "smb", "rdp", "telnet", "mysql", "postgres", "mssql", "redis", "mongo", "dns"}


class ReconAssetAnalyzer:
    """Analyzes and classifies graph nodes as recon assets.

    Usage::

        analyzer = ReconAssetAnalyzer(graph)
        assets = analyzer.analyze()
    """

    def __init__(self, graph: AttackGraph) -> None:
        self._graph = graph

    def analyze(self) -> list[ReconAsset]:
        """Classify all non-entrypoint graph nodes as recon assets."""
        assets: list[ReconAsset] = []

        for node in self._graph.nodes.values():
            if node.node_type == "entrypoint":
                continue

            asset_class = self._classify(node)
            assets.append(ReconAsset(
                node_id=node.id,
                label=node.label,
                asset_class=asset_class,
                node_type=node.node_type,
                properties=dict(node.properties),
            ))

        logger.info("Analyzed %d assets from graph", len(assets))
        return assets

    def _classify(self, node: AttackNode) -> str:
        """Classify a single node into an asset class."""
        label_lower = node.label.lower()
        atype = str(node.properties.get("artifact_type", "")).lower()
        combined = f"{label_lower} {atype}"

        # Subdomains
        if node.node_type == "asset" and "subdomain" in atype:
            return "subdomain"

        # Cloud assets
        if any(ind in combined for ind in _CLOUD_INDICATORS):
            return "cloud_asset"

        # Services
        if node.node_type == "service":
            if any(ind in combined for ind in _WEB_INDICATORS):
                return "web_service"
            if any(ind in combined for ind in _NETWORK_SERVICES):
                return "network_service"
            return "network_service"

        # Endpoints
        if node.node_type == "endpoint":
            if any(ind in combined for ind in _API_INDICATORS):
                return "api_endpoint"
            return "web_endpoint"

        # Generic assets
        if node.node_type == "asset":
            return "subdomain"

        # Vulnerabilities, credentials, privileges — not recon targets
        return node.node_type
