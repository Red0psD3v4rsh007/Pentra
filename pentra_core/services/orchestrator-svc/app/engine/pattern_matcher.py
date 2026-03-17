"""Pattern matcher — matches attack pattern preconditions against the graph.

MOD-09.5: Analyzes graph nodes and determines which attack patterns
have their preconditions satisfied, enabling knowledge-driven exploration.
"""

from __future__ import annotations

__classification__ = "runtime_optional"

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.attack_graph_builder import AttackGraph, AttackNode
from app.knowledge.pattern_registry import AttackPattern, PatternPrecondition, PatternRegistry

logger = logging.getLogger(__name__)


@dataclass
class PatternMatch:
    """Result of a successful pattern match against the graph."""

    pattern: AttackPattern
    matched_nodes: dict[str, list[str]]  # precondition_type → list of node_ids
    confidence: float   # 0.0–1.0 based on how many preconditions matched

    def to_dict(self) -> dict:
        return {
            "pattern_name": self.pattern.name,
            "domain": self.pattern.domain,
            "confidence": self.confidence,
            "matched_node_count": sum(len(v) for v in self.matched_nodes.values()),
        }


class PatternMatcher:
    """Matches attack patterns against graph nodes.

    Usage::

        matcher = PatternMatcher(registry, graph)
        matches = matcher.match_all()
    """

    def __init__(self, registry: PatternRegistry, graph: AttackGraph) -> None:
        self._registry = registry
        self._graph = graph
        # Index nodes by type
        self._nodes_by_type: dict[str, list[AttackNode]] = {}
        for node in graph.nodes.values():
            if node.node_type != "entrypoint":
                self._nodes_by_type.setdefault(node.node_type, []).append(node)

    def match_all(self, *, domain: str | None = None) -> list[PatternMatch]:
        """Match all patterns against the current graph.

        Returns list of PatternMatch sorted by confidence descending.
        """
        patterns = self._registry.get_patterns(domain=domain)
        matches: list[PatternMatch] = []

        for pattern in patterns:
            match = self._match_pattern(pattern)
            if match is not None:
                matches.append(match)

        matches.sort(key=lambda m: m.confidence, reverse=True)

        logger.info(
            "Pattern matching: %d/%d patterns matched",
            len(matches), len(patterns),
        )
        return matches

    def _match_pattern(self, pattern: AttackPattern) -> PatternMatch | None:
        """Check if a pattern's preconditions are satisfied."""
        matched_nodes: dict[str, list[str]] = {}
        total_preconds = len(pattern.preconditions)
        satisfied = 0

        for precond in pattern.preconditions:
            matching = self._find_matching_nodes(precond)
            if matching:
                matched_nodes[precond.artifact_type] = [n.id for n in matching]
                satisfied += 1

        if satisfied == 0:
            return None

        confidence = satisfied / total_preconds if total_preconds > 0 else 0.0

        # Require at least 50% of preconditions to be satisfied
        if confidence < 0.5:
            return None

        return PatternMatch(
            pattern=pattern,
            matched_nodes=matched_nodes,
            confidence=round(confidence, 2),
        )

    def _find_matching_nodes(self, precond: PatternPrecondition) -> list[AttackNode]:
        """Find graph nodes matching a precondition."""
        # Map precondition artifact_type to graph node_type
        type_map = {
            "endpoint": "endpoint",
            "service": "service",
            "asset": "asset",
            "vulnerability": "vulnerability",
            "credential": "credential",
            "privilege": "privilege",
        }

        node_type = type_map.get(precond.artifact_type)
        if node_type is None:
            return []

        candidates = self._nodes_by_type.get(node_type, [])
        if not candidates:
            return []

        if not precond.filter:
            return candidates

        # Apply filters
        filtered: list[AttackNode] = []
        for node in candidates:
            if self._node_matches_filter(node, precond.filter):
                filtered.append(node)

        return filtered

    def _node_matches_filter(self, node: AttackNode, filters: dict) -> bool:
        """Check if a node matches filter conditions."""
        for key, value in filters.items():
            if key == "label_contains":
                label = node.label.lower()
                if not any(v.lower() in label for v in value):
                    return False

            elif key == "artifact_type_contains":
                atype = str(node.properties.get("artifact_type", "")).lower()
                label = node.label.lower()
                combined = f"{atype} {label}"
                if not any(v.lower() in combined for v in value):
                    return False

            else:
                if node.properties.get(key) != value:
                    return False

        return True
