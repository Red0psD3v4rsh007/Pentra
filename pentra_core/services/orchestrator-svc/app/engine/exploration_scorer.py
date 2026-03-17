"""Exploration scorer — scores and prioritizes exploration hypotheses.

MOD-09: Ranks hypotheses by likelihood of producing new vulnerabilities.

Scoring signals:
  - Asset criticality       (0.35)
  - Exploit probability     (0.25)
  - Privilege potential      (0.20)
  - Path efficiency          (0.20)
"""

from __future__ import annotations

__classification__ = "runtime_optional"

import logging
from dataclasses import dataclass
from typing import Any

from app.engine.attack_graph_builder import AttackGraph
from app.engine.hypothesis_generator import Hypothesis

logger = logging.getLogger(__name__)


_SCORE_WEIGHTS = {
    "asset_value": 0.35,
    "exploit_probability": 0.25,
    "privilege_potential": 0.20,
    "path_efficiency": 0.20,
}

# Hypothesis type → base exploit probability
_TYPE_PROBABILITY: dict[str, float] = {
    "endpoint_fuzz": 7.0,
    "param_mutation": 6.5,
    "credential_reuse": 8.0,
    "service_pivot": 5.0,
    "route_guess": 4.0,
    "api_discovery": 5.5,
}

# Target node type → asset value
_NODE_ASSET_VALUE: dict[str, float] = {
    "endpoint": 7.0,
    "service": 6.0,
    "asset": 5.0,
    "vulnerability": 9.0,
    "credential": 8.0,
    "privilege": 10.0,
}

# Hypothesis type → privilege potential
_TYPE_PRIVILEGE: dict[str, float] = {
    "endpoint_fuzz": 5.0,
    "param_mutation": 6.0,
    "credential_reuse": 9.0,
    "service_pivot": 7.0,
    "route_guess": 3.0,
    "api_discovery": 4.0,
}


@dataclass
class ScoredHypothesis:
    """A hypothesis with computed exploration score."""

    hypothesis: Hypothesis
    total_score: float
    asset_score: float
    exploit_score: float
    privilege_score: float
    efficiency_score: float
    priority: str   # critical | high | medium | low


class ExplorationScorer:
    """Scores and ranks exploration hypotheses.

    Usage::

        scorer = ExplorationScorer(graph)
        scored = scorer.score(hypotheses)
    """

    def __init__(self, graph: AttackGraph) -> None:
        self._graph = graph

    def score(
        self,
        hypotheses: list[Hypothesis],
        *,
        min_score: float = 3.0,
    ) -> list[ScoredHypothesis]:
        """Score all hypotheses and return filtered + sorted list."""
        scored: list[ScoredHypothesis] = []

        for h in hypotheses:
            sh = self._score_one(h)
            if sh.total_score >= min_score:
                scored.append(sh)

        scored.sort(key=lambda s: s.total_score, reverse=True)

        logger.info(
            "Scored %d hypotheses: %d above threshold (%.1f)",
            len(hypotheses), len(scored), min_score,
        )
        return scored

    def _score_one(self, h: Hypothesis) -> ScoredHypothesis:
        # 1 — Asset value
        target_node = self._graph.nodes.get(h.target_node_id)
        node_type = target_node.node_type if target_node else "asset"
        asset = _NODE_ASSET_VALUE.get(node_type, 5.0)

        # 2 — Exploit probability
        exploit = _TYPE_PROBABILITY.get(h.hypothesis_type, 5.0)

        # 3 — Privilege potential
        privilege = _TYPE_PRIVILEGE.get(h.hypothesis_type, 5.0)

        # 4 — Path efficiency (lower complexity = higher score)
        if h.estimated_complexity == 1:
            efficiency = 9.0
        elif h.estimated_complexity == 2:
            efficiency = 6.0
        else:
            efficiency = 3.0

        total = (
            asset * _SCORE_WEIGHTS["asset_value"]
            + exploit * _SCORE_WEIGHTS["exploit_probability"]
            + privilege * _SCORE_WEIGHTS["privilege_potential"]
            + efficiency * _SCORE_WEIGHTS["path_efficiency"]
        )
        total = min(10.0, max(0.0, total))

        return ScoredHypothesis(
            hypothesis=h,
            total_score=round(total, 2),
            asset_score=round(asset, 2),
            exploit_score=round(exploit, 2),
            privilege_score=round(privilege, 2),
            efficiency_score=round(efficiency, 2),
            priority=self._priority_level(total),
        )

    def _priority_level(self, score: float) -> str:
        if score >= 8.0:
            return "critical"
        elif score >= 6.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        else:
            return "low"
