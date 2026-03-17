"""Graph correlator — infers additional relationships in the attack graph.

MOD-08 Phase 1: Analyzes attack graph nodes and edges to discover
implicit relationships not captured by static type-based inference rules.

Correlation categories:

  1. Credential reuse     — same credential across services → lateral movement
  2. Config leak          — leaked config → hidden endpoints, internal services
  3. Cloud escalation     — S3 exposure → source leak → API keys → cloud privesc
  4. Service chaining     — related services on same host → pivot opportunity
  5. Auth relationship    — auth bypass + credential → expanded access

The correlator operates on the in-memory AttackGraph and adds new edges.
It does NOT modify database schemas or scan_artifacts.
"""

from __future__ import annotations

__classification__ = "runtime_optional"

import ipaddress
import logging
from dataclasses import dataclass
from typing import Any

from app.engine.attack_graph_builder import AttackGraph, AttackEdge, AttackNode

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CorrelationRule:
    """Defines a correlation rule for inferring graph edges."""

    name: str
    description: str
    source_type: str          # node_type to match for source
    target_type: str          # node_type to match for target
    edge_type: str            # edge type to create
    source_filter: dict       # property conditions on source node
    target_filter: dict       # property conditions on target node
    bidirectional: bool = False


# ── Correlation rules ────────────────────────────────────────────────

CORRELATION_RULES: list[CorrelationRule] = [
    # 1 — Credential reuse: same credentials across different services
    CorrelationRule(
        name="credential_reuse",
        description="Credentials found in one service may grant access to others",
        source_type="credential",
        target_type="service",
        edge_type="lateral_movement",
        source_filter={},
        target_filter={},
    ),

    # 2 — Config leak → hidden endpoints
    CorrelationRule(
        name="config_leak_endpoints",
        description="Leaked configuration files may reveal hidden endpoints",
        source_type="vulnerability",
        target_type="endpoint",
        edge_type="discovery",
        source_filter={"artifact_type_contains": ["lfi", "config", "leak", "exposure"]},
        target_filter={},
    ),

    # 3 — Cloud privilege escalation chain
    CorrelationRule(
        name="cloud_privesc",
        description="Cloud resource exposure → API keys → privilege escalation",
        source_type="credential",
        target_type="privilege",
        edge_type="privilege_escalation",
        source_filter={"label_contains": ["api_key", "token", "secret", "aws", "cloud"]},
        target_filter={},
    ),

    # 4 — Service chaining on same host
    CorrelationRule(
        name="service_chaining",
        description="Multiple services on same asset enable pivot opportunities",
        source_type="service",
        target_type="service",
        edge_type="lateral_movement",
        source_filter={},
        target_filter={},
    ),

    # 5 — Vulnerability → credential extraction
    CorrelationRule(
        name="vuln_credential_extraction",
        description="Exploitable vulnerabilities may leak credentials",
        source_type="vulnerability",
        target_type="credential",
        edge_type="exploit",
        source_filter={"artifact_type_contains": ["sql_injection", "lfi", "rce", "auth_bypass"]},
        target_filter={},
    ),

    # 6 — Privilege → privilege escalation (different privilege types)
    CorrelationRule(
        name="privilege_chain",
        description="Lower privileges can lead to higher privileges",
        source_type="privilege",
        target_type="privilege",
        edge_type="privilege_escalation",
        source_filter={},
        target_filter={},
    ),

    # 7 — Asset to asset lateral movement
    CorrelationRule(
        name="asset_lateral",
        description="Discovered assets on same subnet enable lateral movement",
        source_type="asset",
        target_type="asset",
        edge_type="lateral_movement",
        source_filter={},
        target_filter={},
    ),
]


# ── Graph Correlator ─────────────────────────────────────────────────


class GraphCorrelator:
    """Analyzes the attack graph and infers additional edges.

    Usage::

        correlator = GraphCorrelator()
        new_edges = correlator.correlate(graph)
    """

    def __init__(self, rules: list[CorrelationRule] | None = None) -> None:
        self._rules = rules if rules is not None else CORRELATION_RULES

    def correlate(self, graph: AttackGraph) -> list[AttackEdge]:
        """Analyze the graph and add inferred edges.

        Returns the list of new edges added.
        """
        existing_pairs = {(e.source, e.target) for e in graph.edges}
        new_edges: list[AttackEdge] = []

        # Index nodes by type for fast lookup
        nodes_by_type: dict[str, list[AttackNode]] = {}
        for node in graph.nodes.values():
            nodes_by_type.setdefault(node.node_type, []).append(node)

        for rule in self._rules:
            sources = nodes_by_type.get(rule.source_type, [])
            targets = nodes_by_type.get(rule.target_type, [])

            if not sources or not targets:
                continue

            for src in sources:
                if not self._matches_filter(src, rule.source_filter):
                    continue

                for tgt in targets:
                    if src.id == tgt.id:
                        continue
                    if not self._matches_filter(tgt, rule.target_filter):
                        continue

                    # Skip self-type edges for same artifact
                    if (rule.source_type == rule.target_type
                            and src.properties.get("artifact_id") == tgt.properties.get("artifact_id")
                            and src.properties.get("artifact_id")):
                        continue

                    # Skip if edge already exists
                    if (src.id, tgt.id) in existing_pairs:
                        continue
                    if not self._should_correlate(rule, src, tgt):
                        continue

                    edge = AttackEdge(
                        source=src.id,
                        target=tgt.id,
                        edge_type=rule.edge_type,
                        properties={
                            "inferred": True,
                            "correlation_rule": rule.name,
                            "description": rule.description,
                        },
                    )
                    graph.add_edge(edge)
                    existing_pairs.add((src.id, tgt.id))
                    new_edges.append(edge)

                    if rule.bidirectional and (tgt.id, src.id) not in existing_pairs:
                        rev = AttackEdge(
                            source=tgt.id,
                            target=src.id,
                            edge_type=rule.edge_type,
                            properties={
                                "inferred": True,
                                "correlation_rule": rule.name,
                                "reverse": True,
                            },
                        )
                        graph.add_edge(rev)
                        existing_pairs.add((tgt.id, src.id))
                        new_edges.append(rev)

        logger.info(
            "Graph correlation: %d new edges inferred from %d rules",
            len(new_edges), len(self._rules),
        )
        return new_edges

    def _should_correlate(
        self,
        rule: CorrelationRule,
        source: AttackNode,
        target: AttackNode,
    ) -> bool:
        if rule.name == "service_chaining":
            return self._share_host_context(source, target)
        if rule.name == "asset_lateral":
            return self._share_network_context(source, target)
        if rule.name == "privilege_chain":
            return self._is_privilege_progression(source, target)
        return True

    def _matches_filter(self, node: AttackNode, filters: dict) -> bool:
        """Check if a node matches the filter conditions."""
        if not filters:
            return True

        for key, value in filters.items():
            if key == "artifact_type_contains":
                node_atype = str(node.properties.get("artifact_type", "")).lower()
                node_label = node.label.lower()
                node_text = f"{node_atype} {node_label}"
                if not any(v.lower() in node_text for v in value):
                    return False

            elif key == "label_contains":
                label = node.label.lower()
                props_text = str(node.properties).lower()
                combined = f"{label} {props_text}"
                if not any(v.lower() in combined for v in value):
                    return False

            else:
                # Direct property match
                if node.properties.get(key) != value:
                    return False

        return True

    def _share_host_context(self, source: AttackNode, target: AttackNode) -> bool:
        source_host = self._node_context(source, ("host", "target"))
        target_host = self._node_context(target, ("host", "target"))

        if source_host and target_host:
            return source_host == target_host

        return True

    def _share_network_context(self, source: AttackNode, target: AttackNode) -> bool:
        source_network = self._network_context(source)
        target_network = self._network_context(target)

        if not source_network or not target_network:
            return False

        return source_network == target_network

    def _is_privilege_progression(self, source: AttackNode, target: AttackNode) -> bool:
        if not self._share_target_context(source, target):
            return False

        return self._privilege_rank(source) < self._privilege_rank(target)

    def _share_target_context(self, source: AttackNode, target: AttackNode) -> bool:
        source_target = self._node_context(source, ("target", "host", "endpoint", "url"))
        target_target = self._node_context(target, ("target", "host", "endpoint", "url"))

        if source_target and target_target:
            return (
                source_target == target_target
                or source_target in target_target
                or target_target in source_target
            )

        return False

    def _node_context(self, node: AttackNode, keys: tuple[str, ...]) -> str:
        for key in keys:
            value = node.properties.get(key)
            if value:
                return str(value).lower()
        return ""

    def _network_context(self, node: AttackNode) -> str:
        for key in ("subnet", "cidr"):
            value = node.properties.get(key)
            if value:
                return str(value)

        for key in ("ip", "host", "target"):
            value = node.properties.get(key)
            if not value:
                continue
            try:
                address = ipaddress.ip_address(str(value))
            except ValueError:
                continue

            if address.version == 4:
                return str(ipaddress.ip_network(f"{address}/24", strict=False))
            return str(ipaddress.ip_network(f"{address}/64", strict=False))

        return ""

    def _privilege_rank(self, node: AttackNode) -> int:
        artifact_type = str(node.properties.get("artifact_type") or "").lower()
        access_text = " ".join(
            str(value).lower()
            for value in (
                node.properties.get("access_level"),
                node.properties.get("target"),
                node.label,
                artifact_type,
            )
            if value
        )

        rank = {
            "access_levels": 1,
            "database_access": 2,
            "shell_access": 3,
            "verified_impact": 4,
            "privilege_escalation": 5,
        }.get(artifact_type, 0)

        if any(token in access_text for token in ("read", "viewer", "user", "basic")):
            rank = max(rank, 1)
        if any(token in access_text for token in ("db", "database", "dba")):
            rank = max(rank, 2)
        if any(token in access_text for token in ("shell", "command", "exec")):
            rank = max(rank, 3)
        if any(token in access_text for token in ("admin", "root", "system", "superuser")):
            rank = max(rank, 4)

        return rank

    def get_correlation_summary(self, new_edges: list[AttackEdge]) -> dict:
        """Summarize correlation results."""
        if not new_edges:
            return {"total_inferred": 0, "rules_triggered": [], "root_cause_groups": []}

        rules_triggered: dict[str, int] = {}
        edge_type_counts: dict[str, int] = {}
        for e in new_edges:
            rule = e.properties.get("correlation_rule", "unknown")
            rules_triggered[rule] = rules_triggered.get(rule, 0) + 1
            edge_type_counts[e.edge_type] = edge_type_counts.get(e.edge_type, 0) + 1

        return {
            "total_inferred": len(new_edges),
            "rules_triggered": [
                {"rule": r, "edges_added": c}
                for r, c in sorted(rules_triggered.items(), key=lambda x: -x[1])
            ],
            "edge_types": dict(sorted(edge_type_counts.items(), key=lambda x: -x[1])),
            "root_cause_groups": self.group_by_root_cause(new_edges),
        }

    def group_by_root_cause(self, edges: list[AttackEdge]) -> list[dict[str, Any]]:
        """Group correlated edges by their source vulnerability type.

        When multiple paths lead to the same target via the same vulnerability type,
        group them under a single 'attack narrative' to reduce noise.
        """
        groups: dict[str, dict[str, Any]] = {}
        for edge in edges:
            rule = str(edge.properties.get("correlation_rule", "unknown"))
            source_node = self._graph.nodes.get(edge.source) if hasattr(self, "_graph") else None
            target_node = self._graph.nodes.get(edge.target) if hasattr(self, "_graph") else None

            source_type = source_node.properties.get("artifact_type", source_node.label) if source_node else edge.source
            target_label = target_node.label if target_node else edge.target

            key = f"{source_type}:{edge.edge_type}:{target_label}"
            group = groups.setdefault(key, {
                "root_cause": str(source_type),
                "edge_type": edge.edge_type,
                "target": str(target_label),
                "correlation_rule": rule,
                "path_count": 0,
                "sources": set(),
                "targets": set(),
            })
            group["path_count"] += 1
            group["sources"].add(edge.source)
            group["targets"].add(edge.target)

        narratives = []
        for group in groups.values():
            narratives.append({
                "root_cause": group["root_cause"],
                "edge_type": group["edge_type"],
                "target": group["target"],
                "correlation_rule": group["correlation_rule"],
                "path_count": group["path_count"],
                "unique_sources": len(group["sources"]),
                "unique_targets": len(group["targets"]),
                "narrative": (
                    f"{group['root_cause']} enables {group['edge_type']} "
                    f"to {group['target']} ({group['path_count']} paths)"
                ),
            })

        narratives.sort(key=lambda x: -x["path_count"])
        return narratives[:20]

    def _graph(self) -> AttackGraph:
        """Access the stored graph reference (set during correlate)."""
        raise AttributeError("Graph not available outside correlate()")

