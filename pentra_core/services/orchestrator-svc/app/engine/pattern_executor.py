"""Pattern executor — converts matched patterns into exploration hypotheses.

MOD-09.5: Takes PatternMatch results and generates Hypothesis objects
that the ExplorationEngine can score, budget-check, and convert to
dynamic scan_nodes.
"""

from __future__ import annotations

import logging
from typing import Any

from app.engine.attack_graph_builder import AttackGraph
from app.engine.hypothesis_generator import Hypothesis
from app.engine.pattern_matcher import PatternMatch

logger = logging.getLogger(__name__)


class PatternExecutor:
    """Converts matched patterns into exploration hypotheses.

    Usage::

        executor = PatternExecutor(graph)
        hypotheses = executor.generate_hypotheses(matches)
    """

    def __init__(self, graph: AttackGraph) -> None:
        self._graph = graph

    def generate_hypotheses(
        self,
        matches: list[PatternMatch],
        *,
        max_per_pattern: int = 5,
    ) -> list[Hypothesis]:
        """Convert pattern matches into exploration hypotheses.

        Each pattern match generates one hypothesis per matched target node,
        up to max_per_pattern per pattern.
        """
        hypotheses: list[Hypothesis] = []

        for match in matches:
            generated = self._generate_from_match(match, max_per_pattern=max_per_pattern)
            hypotheses.extend(generated)

        logger.info(
            "PatternExecutor: %d hypotheses from %d pattern matches",
            len(hypotheses), len(matches),
        )
        return hypotheses

    def _generate_from_match(
        self,
        match: PatternMatch,
        *,
        max_per_pattern: int,
    ) -> list[Hypothesis]:
        """Generate hypotheses from a single pattern match."""
        pattern = match.pattern
        results: list[Hypothesis] = []
        count = 0

        # Collect all matched target node IDs
        all_node_ids: list[str] = []
        for nids in match.matched_nodes.values():
            all_node_ids.extend(nids)

        # Deduplicate
        seen: set[str] = set()

        for node_id in all_node_ids:
            if count >= max_per_pattern:
                break
            if node_id in seen:
                continue
            seen.add(node_id)

            node = self._graph.nodes.get(node_id)
            if node is None:
                continue

            for action in pattern.actions:
                if count >= max_per_pattern:
                    break

                h = Hypothesis(
                    hypothesis_id=f"pat:{pattern.name}:{node_id}:{action.tool}",
                    hypothesis_type=f"pattern_{pattern.name}",
                    target_node_id=node_id,
                    target_label=node.label,
                    description=f"{action.description} [{pattern.domain}:{pattern.name}]",
                    tool=action.tool,
                    worker_family=action.worker_family,
                    config={
                        "pattern_name": pattern.name,
                        "pattern_domain": pattern.domain,
                        "confidence": match.confidence,
                        "impact": pattern.impact,
                        "target_type": node.node_type,
                        "artifact_type": node.properties.get("artifact_type", ""),
                        "no_persist": True,
                    },
                    required_artifacts=[p.artifact_type for p in pattern.preconditions],
                    estimated_complexity=2 if len(pattern.preconditions) > 1 else 1,
                    timeout_seconds=action.timeout,
                )
                results.append(h)
                count += 1

        return results
