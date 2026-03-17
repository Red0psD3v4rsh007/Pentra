"""Cross-domain correlator — connects web, cloud, network, and identity artifacts.

MOD-12.5: Discovers cross-domain attack paths by correlating assets
across different domains (e.g., SSRF → metadata → cloud credentials,
credential → SSH → internal network).
"""

from __future__ import annotations

__classification__ = "experimental"

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.asset_graph_builder import AssetGraph, AssetNode, AssetRelation

logger = logging.getLogger(__name__)


@dataclass
class CrossDomainPath:
    """An attack path spanning multiple domains."""

    path_id: str
    domains_crossed: list[str]
    nodes: list[str]
    labels: list[str]
    relation_types: list[str]
    risk_multiplier: float = 1.0

    def to_dict(self) -> dict:
        return {
            "path_id": self.path_id,
            "domains": self.domains_crossed,
            "length": len(self.nodes),
            "risk_multiplier": self.risk_multiplier,
        }


# ── Correlation rules ────────────────────────────────────────────

@dataclass
class CorrelationRule:
    """Rule for cross-domain correlation."""

    name: str
    source_domain: str
    target_domain: str
    source_type: str
    target_type: str
    relation: str
    risk_multiplier: float
    description: str


_CORRELATION_RULES: list[CorrelationRule] = [
    CorrelationRule("ssrf_to_cloud", "web", "cloud", "endpoint", "cloud_resource",
                    "exposes", 2.0, "SSRF from web to cloud metadata"),
    CorrelationRule("cred_to_service", "identity", "network", "credential", "service",
                    "authenticates", 1.5, "Credential authenticates network service"),
    CorrelationRule("repo_to_cred", "code", "identity", "repository", "credential",
                    "stores", 1.8, "Repository contains leaked credentials"),
    CorrelationRule("cloud_to_network", "cloud", "network", "cloud_resource", "service",
                    "connects", 1.5, "Cloud resource exposes network service"),
    CorrelationRule("web_to_identity", "web", "identity", "endpoint", "credential",
                    "exposes", 1.6, "Web endpoint leaks credentials"),
    CorrelationRule("identity_to_cloud", "identity", "cloud", "credential", "cloud_resource",
                    "authenticates", 2.0, "Credential grants cloud access"),
    CorrelationRule("network_to_identity", "network", "identity", "service", "identity",
                    "exposes", 1.4, "Network service exposes identity system"),
]


class CrossDomainCorrelator:
    """Discovers cross-domain attack paths.

    Usage::

        correlator = CrossDomainCorrelator()
        paths = correlator.correlate(asset_graph)
    """

    def __init__(self, rules: list[CorrelationRule] | None = None) -> None:
        self._rules = rules or _CORRELATION_RULES

    def correlate(self, graph: AssetGraph) -> list[CrossDomainPath]:
        """Find cross-domain attack paths."""
        paths: list[CrossDomainPath] = []

        # Apply correlation rules to create new relations
        new_relations = self._apply_rules(graph)
        for rel in new_relations:
            graph.add_relation(rel)

        # Discover multi-domain paths via BFS
        paths = self._discover_paths(graph)

        logger.info("CrossDomainCorrelator: %d paths, %d new relations",
                     len(paths), len(new_relations))
        return paths

    def _apply_rules(self, graph: AssetGraph) -> list[AssetRelation]:
        """Apply correlation rules to discover implicit cross-domain connections."""
        new_rels: list[AssetRelation] = []
        existing = {(r.source, r.target) for r in graph.relations}

        for rule in self._rules:
            sources = [n for n in graph.nodes.values()
                       if n.domain == rule.source_domain and n.asset_type == rule.source_type]
            targets = [n for n in graph.nodes.values()
                       if n.domain == rule.target_domain and n.asset_type == rule.target_type]

            for src in sources:
                for tgt in targets:
                    if src.id != tgt.id and (src.id, tgt.id) not in existing:
                        new_rels.append(AssetRelation(
                            source=src.id, target=tgt.id,
                            relation_type=rule.relation,
                            properties={"rule": rule.name, "risk_multiplier": rule.risk_multiplier},
                        ))
                        existing.add((src.id, tgt.id))

        return new_rels

    def _discover_paths(self, graph: AssetGraph) -> list[CrossDomainPath]:
        """Discover paths that cross domain boundaries."""
        adj: dict[str, list[tuple[str, str]]] = {}
        for rel in graph.relations:
            adj.setdefault(rel.source, []).append((rel.target, rel.relation_type))

        paths: list[CrossDomainPath] = []
        path_count = 0

        for start_id, start_node in graph.nodes.items():
            if path_count >= 50:
                break
            visited = {start_id}
            queue: list[tuple[list[str], list[str], list[str]]] = [
                ([start_id], [start_node.label], [])
            ]
            while queue and path_count < 50:
                node_ids, labels, rels = queue.pop(0)
                current = node_ids[-1]

                for neighbor_id, rel_type in adj.get(current, []):
                    if neighbor_id in visited or neighbor_id not in graph.nodes:
                        continue
                    neighbor = graph.nodes[neighbor_id]
                    new_ids = node_ids + [neighbor_id]
                    new_labels = labels + [neighbor.label]
                    new_rels = rels + [rel_type]

                    domains = list(dict.fromkeys(
                        graph.nodes[n].domain for n in new_ids if n in graph.nodes
                    ))
                    if len(domains) >= 2:
                        risk = 1.0
                        for rel in graph.relations:
                            if rel.source in new_ids and rel.target in new_ids:
                                risk = max(risk, rel.properties.get("risk_multiplier", 1.0))
                        paths.append(CrossDomainPath(
                            path_id=f"xdomain:{path_count}",
                            domains_crossed=domains,
                            nodes=new_ids, labels=new_labels,
                            relation_types=new_rels,
                            risk_multiplier=risk,
                        ))
                        path_count += 1

                    if len(new_ids) < 5:
                        visited.add(neighbor_id)
                        queue.append((new_ids, new_labels, new_rels))

        paths.sort(key=lambda p: (len(p.domains_crossed), p.risk_multiplier), reverse=True)
        return paths
