"""Heuristic test generator — converts heuristic matches into hypotheses.

MOD-11: Takes HeuristicMatch results and generates Hypothesis objects
for dynamic vulnerability testing via the exploration pipeline.
"""

from __future__ import annotations

__classification__ = "runtime_optional"

import logging
from typing import Any

from app.engine.attack_graph_builder import AttackGraph
from app.engine.hypothesis_generator import Hypothesis
from app.engine.heuristic_matcher import HeuristicMatch

logger = logging.getLogger(__name__)


class HeuristicTestGenerator:
    """Converts heuristic matches into exploration hypotheses.

    Usage::

        gen = HeuristicTestGenerator(graph)
        hypotheses = gen.generate(matches)
    """

    def __init__(self, graph: AttackGraph) -> None:
        self._graph = graph

    def generate(
        self,
        matches: list[HeuristicMatch],
        *,
        max_per_heuristic: int = 3,
    ) -> list[Hypothesis]:
        """Convert heuristic matches into hypotheses.

        Each match becomes one hypothesis per action, capped by max_per_heuristic
        per heuristic definition.
        """
        hypotheses: list[Hypothesis] = []
        count_by_heuristic: dict[str, int] = {}

        for match in matches:
            h_name = match.heuristic.name
            count = count_by_heuristic.get(h_name, 0)
            if count >= max_per_heuristic:
                continue

            for action in match.heuristic.actions:
                if count_by_heuristic.get(h_name, 0) >= max_per_heuristic:
                    break

                hyp = Hypothesis(
                    hypothesis_id=f"heur:{h_name}:{match.matched_node_id}:{action.get('test_type', action['tool'])}",
                    hypothesis_type=f"heuristic_{h_name}",
                    target_node_id=match.matched_node_id,
                    target_label=match.matched_label,
                    description=f"{action.get('description', match.heuristic.description)} [heuristic:{h_name}]",
                    tool=action["tool"],
                    worker_family=action.get("worker_family", "exploit"),
                    config={
                        "heuristic_name": h_name,
                        "heuristic_category": match.heuristic.category,
                        "vulnerability_class": match.heuristic.vulnerability_class,
                        "test_type": action.get("test_type", ""),
                        "confidence": match.heuristic.confidence,
                        "matched_indicators": match.matched_indicators,
                        "impact": match.heuristic.impact,
                        "no_persist": True,
                    },
                    required_artifacts=[match.heuristic.node_type],
                    estimated_complexity=2,
                    timeout_seconds=action.get("timeout", 300),
                )
                hypotheses.append(hyp)
                count_by_heuristic[h_name] = count_by_heuristic.get(h_name, 0) + 1

        logger.info(
            "HeuristicTestGenerator: %d hypotheses from %d matches",
            len(hypotheses), len(matches),
        )
        return hypotheses
