"""Pattern graph builder — builds a graph of attack pattern relationships.

MOD-09.6: Analyzes attack patterns and connects them by their
impact→precondition relationships, enabling multi-step chain reasoning.

Example:
  credential_reuse_ssh (impact: shell_access)
  → can feed into patterns requiring credential or privilege preconditions

The pattern graph is a directed graph where edges represent
"output of pattern A can satisfy preconditions of pattern B".
"""

from __future__ import annotations

__classification__ = "runtime_optional"

import logging
from dataclasses import dataclass, field
from typing import Any

from app.knowledge.pattern_registry import AttackPattern, PatternRegistry

logger = logging.getLogger(__name__)


# ── Impact → precondition type mapping ───────────────────────────────
# Maps pattern impact types to the artifact types they produce,
# enabling precondition matching for downstream patterns.

_IMPACT_TO_ARTIFACT: dict[str, list[str]] = {
    "shell_access": ["credential", "privilege"],
    "database_access": ["credential", "privilege"],
    "admin_access": ["credential", "privilege"],
    "credential_leak": ["credential"],
    "data_exposure": ["credential", "vulnerability"],
    "privilege_escalation": ["privilege"],
    "lateral_movement": ["service", "asset"],
    "session_hijack": ["credential"],
    "internal_access": ["service", "endpoint", "asset"],
}


@dataclass
class PatternEdge:
    """An edge in the pattern graph linking two patterns."""

    source_pattern: str     # pattern name
    target_pattern: str     # pattern name
    link_type: str          # impact type that connects them
    produced_artifact: str  # artifact type produced by source


@dataclass
class PatternGraph:
    """A directed graph of attack pattern relationships."""

    edges: list[PatternEdge] = field(default_factory=list)
    adjacency: dict[str, list[str]] = field(default_factory=dict)  # source → [targets]
    reverse: dict[str, list[str]] = field(default_factory=dict)    # target → [sources]

    def add_edge(self, edge: PatternEdge) -> None:
        self.edges.append(edge)
        self.adjacency.setdefault(edge.source_pattern, []).append(edge.target_pattern)
        self.reverse.setdefault(edge.target_pattern, []).append(edge.source_pattern)

    def get_successors(self, pattern_name: str) -> list[str]:
        return list(set(self.adjacency.get(pattern_name, [])))

    def get_predecessors(self, pattern_name: str) -> list[str]:
        return list(set(self.reverse.get(pattern_name, [])))

    def to_dict(self) -> dict:
        return {
            "edge_count": len(self.edges),
            "pattern_count": len(set(
                [e.source_pattern for e in self.edges]
                + [e.target_pattern for e in self.edges]
            )),
            "edges": [
                {"source": e.source_pattern, "target": e.target_pattern, "link": e.link_type}
                for e in self.edges
            ],
        }


class PatternGraphBuilder:
    """Builds a graph of attack pattern relationships.

    Usage::

        builder = PatternGraphBuilder(registry)
        graph = builder.build()
    """

    def __init__(self, registry: PatternRegistry) -> None:
        self._registry = registry

    def build(self) -> PatternGraph:
        """Build the pattern relationship graph.

        Connects patterns where one pattern's impact can satisfy
        another pattern's preconditions.
        """
        graph = PatternGraph()
        patterns = self._registry.patterns

        for source in patterns:
            for target in patterns:
                if source.name == target.name:
                    continue

                edges = self._find_connections(source, target)
                for edge in edges:
                    graph.add_edge(edge)

        logger.info(
            "Pattern graph built: %d edges connecting %d patterns",
            len(graph.edges),
            len(set(e.source_pattern for e in graph.edges)
                | set(e.target_pattern for e in graph.edges)),
        )
        return graph

    def _find_connections(
        self, source: AttackPattern, target: AttackPattern,
    ) -> list[PatternEdge]:
        """Find edges where source's impact satisfies target's preconditions."""
        edges: list[PatternEdge] = []
        seen: set[str] = set()

        for impact in source.impact:
            produced_types = _IMPACT_TO_ARTIFACT.get(impact, [])

            for produced in produced_types:
                for precond in target.preconditions:
                    if precond.artifact_type == produced:
                        key = f"{source.name}→{target.name}:{impact}"
                        if key not in seen:
                            seen.add(key)
                            edges.append(PatternEdge(
                                source_pattern=source.name,
                                target_pattern=target.name,
                                link_type=impact,
                                produced_artifact=produced,
                            ))

        return edges
