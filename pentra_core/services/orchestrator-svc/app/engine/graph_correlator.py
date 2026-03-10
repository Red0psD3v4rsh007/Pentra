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

    def get_correlation_summary(self, new_edges: list[AttackEdge]) -> dict:
        """Summarize correlation results."""
        if not new_edges:
            return {"total_inferred": 0, "rules_triggered": []}

        rules_triggered: dict[str, int] = {}
        for e in new_edges:
            rule = e.properties.get("correlation_rule", "unknown")
            rules_triggered[rule] = rules_triggered.get(rule, 0) + 1

        return {
            "total_inferred": len(new_edges),
            "rules_triggered": [
                {"rule": r, "edges_added": c}
                for r, c in sorted(rules_triggered.items(), key=lambda x: -x[1])
            ],
            "edge_types": dict(sorted(
                {e.edge_type for e in new_edges}.__iter__().__class__.__name__
                and [(et, sum(1 for e in new_edges if e.edge_type == et))
                     for et in {e.edge_type for e in new_edges}],
                key=lambda x: -x[1],
            )),
        }
