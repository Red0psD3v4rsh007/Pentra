"""Asset graph builder — unifies discovered assets into a global asset graph.

MOD-12.5: Constructs an organization-wide asset graph connecting
subdomains, services, endpoints, credentials, cloud resources,
repositories, and infrastructure into a unified model.
"""

from __future__ import annotations

__classification__ = "experimental"

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AssetNode:
    """A node in the asset graph."""

    id: str
    asset_type: str        # subdomain | service | endpoint | credential | cloud_resource | repository | network | identity
    label: str
    domain: str            # web | cloud | network | identity | code
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "asset_type": self.asset_type,
            "label": self.label, "domain": self.domain,
        }


@dataclass
class AssetRelation:
    """A relationship between assets."""

    source: str
    target: str
    relation_type: str     # hosts | exposes | authenticates | stores | connects | resolves
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class AssetGraph:
    """Global organizational asset graph."""

    org_id: str
    nodes: dict[str, AssetNode] = field(default_factory=dict)
    relations: list[AssetRelation] = field(default_factory=list)

    def add_node(self, node: AssetNode) -> None:
        self.nodes[node.id] = node

    def add_relation(self, rel: AssetRelation) -> None:
        self.relations.append(rel)

    def get_by_domain(self, domain: str) -> list[AssetNode]:
        return [n for n in self.nodes.values() if n.domain == domain]

    def get_by_type(self, asset_type: str) -> list[AssetNode]:
        return [n for n in self.nodes.values() if n.asset_type == asset_type]

    def get_neighbors(self, node_id: str) -> list[str]:
        return [r.target for r in self.relations if r.source == node_id]

    def to_dict(self) -> dict:
        return {
            "org_id": self.org_id,
            "node_count": len(self.nodes),
            "relation_count": len(self.relations),
            "domains": list({n.domain for n in self.nodes.values()}),
        }


# Domain classification for artifact types
_DOMAIN_MAP: dict[str, str] = {
    "subdomains": "web", "endpoints": "web", "services": "network",
    "credential_leak": "identity", "access_levels": "identity",
    "database_access": "cloud", "shell_access": "network",
    "s3_bucket": "cloud", "ec2_instance": "cloud", "rds_instance": "cloud",
    "repository": "code", "api_key": "identity", "vpn_endpoint": "network",
    "iam_role": "cloud", "certificate": "identity",
}

_ASSET_TYPE_MAP: dict[str, str] = {
    "subdomains": "subdomain", "endpoints": "endpoint", "services": "service",
    "credential_leak": "credential", "access_levels": "credential",
    "database_access": "cloud_resource", "shell_access": "service",
    "s3_bucket": "cloud_resource", "ec2_instance": "cloud_resource",
    "rds_instance": "cloud_resource", "repository": "repository",
    "api_key": "credential", "vpn_endpoint": "network",
    "iam_role": "identity", "certificate": "identity",
}


class AssetGraphBuilder:
    """Builds a unified asset graph from attack graph artifacts.

    Usage::

        builder = AssetGraphBuilder("org-1")
        graph = builder.build_from_attack_graph(attack_graph)
    """

    def __init__(self, org_id: str = "default") -> None:
        self._org_id = org_id

    def build_from_attack_graph(self, attack_graph) -> AssetGraph:
        """Build asset graph from an existing attack graph."""
        ag = AssetGraph(org_id=self._org_id)

        for node_id, node in attack_graph.nodes.items():
            if node.node_type == "entrypoint":
                continue
            artifact_type = node.properties.get("artifact_type", node.node_type)
            domain = _DOMAIN_MAP.get(artifact_type, "web")
            asset_type = _ASSET_TYPE_MAP.get(artifact_type, node.node_type)

            ag.add_node(AssetNode(
                id=node_id, asset_type=asset_type,
                label=node.label, domain=domain,
                properties={**node.properties, "source": "attack_graph"},
            ))

        # Infer relations from attack graph edges
        for edge in attack_graph.edges:
            if edge.source in ag.nodes and edge.target in ag.nodes:
                rel_type = self._infer_relation(edge.edge_type)
                ag.add_relation(AssetRelation(
                    source=edge.source, target=edge.target,
                    relation_type=rel_type,
                ))

        # Auto-connect same-domain assets
        self._connect_domains(ag)

        logger.info("AssetGraph built: %d nodes, %d relations, domains=%s",
                     len(ag.nodes), len(ag.relations),
                     list({n.domain for n in ag.nodes.values()}))
        return ag

    def _infer_relation(self, edge_type: str) -> str:
        return {
            "discovery": "resolves", "exploit": "exposes",
            "credential_usage": "authenticates", "lateral_movement": "connects",
            "privilege_escalation": "exposes",
        }.get(edge_type, "connects")

    def _connect_domains(self, ag: AssetGraph) -> None:
        """Connect credentials to services they could authenticate."""
        creds = ag.get_by_type("credential")
        services = ag.get_by_type("service")
        for cred in creds:
            for svc in services:
                existing = any(
                    r.source == cred.id and r.target == svc.id
                    for r in ag.relations
                )
                if not existing:
                    ag.add_relation(AssetRelation(
                        source=cred.id, target=svc.id,
                        relation_type="authenticates",
                        properties={"inferred": True},
                    ))
