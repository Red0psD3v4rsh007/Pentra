"""Action selector — chooses the next best offensive action.

MOD-12: Evaluates the current attack state and selects the optimal
next action from: exploit chain, deeper recon, expand exploration,
or refine exploit attempts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.attack_planner import AttackPlanner, RankedPath
from app.engine.attack_graph_builder import AttackGraph

logger = logging.getLogger(__name__)


@dataclass
class OffensiveAction:
    """A selected offensive action to execute next."""

    action_id: str
    action_type: str       # exploit_chain | deeper_recon | expand_exploration | refine_exploit
    priority: float        # 0.0–1.0
    description: str
    target_path: RankedPath | None = None
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "priority": round(self.priority, 3),
            "description": self.description,
        }


# ── Action thresholds ────────────────────────────────────────────

_EXPLOIT_THRESHOLD = 0.5       # Score above which we attempt exploitation
_RECON_THRESHOLD = 0.3         # Below exploit but above this → recon
_REFINE_THRESHOLD = 0.2        # Below recon → refine previous attempts


class ActionSelector:
    """Selects the next best offensive action based on attack graph state.

    Usage::

        selector = ActionSelector(graph)
        actions = selector.select(max_actions=3)
    """

    def __init__(self, graph: AttackGraph) -> None:
        self._graph = graph
        self._planner = AttackPlanner(graph)

    def select(self, *, max_actions: int = 5) -> list[OffensiveAction]:
        """Select the optimal next actions based on current graph state."""
        ranked_paths = self._planner.plan(max_paths=20)
        actions: list[OffensiveAction] = []

        graph_stats = self._analyze_graph()

        for i, path in enumerate(ranked_paths[:max_actions]):
            action = self._path_to_action(path, i, graph_stats)
            actions.append(action)

        # If few paths, always add a recon expansion
        if len(ranked_paths) < 3 and graph_stats["endpoint_count"] < 5:
            actions.append(OffensiveAction(
                action_id=f"action:recon_expand",
                action_type="deeper_recon",
                priority=0.6,
                description="Expand reconnaissance — limited attack surface discovered",
                config={"reason": "sparse_graph"},
            ))

        # If we have failed attempts, add refinement
        if graph_stats["vulnerability_count"] > 0 and len(ranked_paths) > 0:
            actions.append(OffensiveAction(
                action_id=f"action:refine",
                action_type="refine_exploit",
                priority=0.4,
                description="Refine exploit attempts on detected vulnerabilities",
                config={"vulnerability_count": graph_stats["vulnerability_count"]},
            ))

        actions.sort(key=lambda a: a.priority, reverse=True)
        result = actions[:max_actions]
        logger.info("ActionSelector: %d actions selected (top: %s)",
                     len(result), result[0].action_type if result else "none")
        return result

    def _path_to_action(self, path: RankedPath, index: int, stats: dict) -> OffensiveAction:
        """Convert a ranked path into an offensive action."""
        if path.score >= _EXPLOIT_THRESHOLD:
            return OffensiveAction(
                action_id=f"action:exploit:{index}",
                action_type="exploit_chain",
                priority=path.score,
                description=f"Execute exploit chain → {path.labels[-1] if path.labels else 'target'}",
                target_path=path,
                config={"path_id": path.path_id, "chain_length": len(path.nodes)},
            )
        elif path.score >= _RECON_THRESHOLD:
            return OffensiveAction(
                action_id=f"action:recon:{index}",
                action_type="deeper_recon",
                priority=path.score,
                description=f"Deeper recon on path toward {path.labels[-1] if path.labels else 'target'}",
                target_path=path,
                config={"path_id": path.path_id},
            )
        elif path.score >= _REFINE_THRESHOLD:
            return OffensiveAction(
                action_id=f"action:explore:{index}",
                action_type="expand_exploration",
                priority=path.score,
                description=f"Expand exploration around {path.labels[-1] if path.labels else 'target'}",
                target_path=path,
                config={"path_id": path.path_id},
            )
        else:
            return OffensiveAction(
                action_id=f"action:refine:{index}",
                action_type="refine_exploit",
                priority=max(path.score, 0.1),
                description=f"Refine low-confidence path toward {path.labels[-1] if path.labels else 'target'}",
                target_path=path,
                config={"path_id": path.path_id},
            )

    def _analyze_graph(self) -> dict[str, int]:
        """Analyze current graph composition."""
        counts: dict[str, int] = {}
        for node in self._graph.nodes.values():
            key = f"{node.node_type}_count"
            counts[key] = counts.get(key, 0) + 1
        return counts
