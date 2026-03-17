"""Strategy engine — selects the highest-impact attack path for execution.

MOD-08 Phase 2: Analyzes scored attack paths from the Attack Graph Engine,
ranks them by offensive impact, and selects the best path for exploit chain
generation and dynamic DAG expansion.

Ranking signals:
  - Risk score (from PathScorer)
  - Privilege escalation potential
  - Path length (shorter = more actionable)
  - Verified exploit availability
  - Asset criticality
"""

from __future__ import annotations

__classification__ = "runtime_optional"

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.attack_graph_builder import AttackGraph
from app.engine.path_enumerator import AttackPath
from app.engine.path_scorer import ScoredPath

logger = logging.getLogger(__name__)


# ── Ranking weights ──────────────────────────────────────────────────

_RANK_WEIGHTS = {
    "risk_score": 0.35,
    "privilege_depth": 0.25,
    "path_efficiency": 0.20,
    "exploit_verified": 0.20,
}

# High-value target artifact types
_HIGH_VALUE_TARGETS = {
    "shell_access": 1.0,
    "database_access": 0.9,
    "privilege_escalation": 0.95,
    "credential_leak": 0.8,
    "admin_access": 1.0,
}


@dataclass
class RankedPath:
    """An attack path with offensive priority ranking."""

    scored_path: ScoredPath
    offensive_score: float   # 0.0–10.0
    rank: int
    rationale: str
    selected: bool = False


@dataclass
class OffensiveStrategy:
    """The selected offensive strategy for execution."""

    scan_id: str
    selected_path: RankedPath
    all_ranked: list[RankedPath]
    target_type: str
    target_label: str
    estimated_steps: int

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "selected_rank": self.selected_path.rank,
            "offensive_score": self.selected_path.offensive_score,
            "target_type": self.target_type,
            "target_label": self.target_label,
            "estimated_steps": self.estimated_steps,
            "rationale": self.selected_path.rationale,
            "total_candidates": len(self.all_ranked),
            "path_nodes": self.selected_path.scored_path.path.nodes,
            "path_edges": self.selected_path.scored_path.path.edges,
        }


class StrategyEngine:
    """Selects the optimal attack path for exploit chain execution.

    Usage::

        engine = StrategyEngine(graph)
        strategy = engine.select_strategy(scored_paths)
    """

    def __init__(self, graph: AttackGraph) -> None:
        self._graph = graph

    def select_strategy(
        self,
        scored_paths: list[ScoredPath],
        *,
        max_candidates: int = 10,
    ) -> OffensiveStrategy | None:
        """Rank paths and select the best one for execution.

        Returns None if no viable paths exist.
        """
        if not scored_paths:
            logger.info("No scored paths available — no strategy")
            return None

        # Rank all paths
        ranked = self._rank_paths(scored_paths)

        if not ranked:
            return None

        # Select top path
        selected = ranked[0]
        selected.selected = True

        # Resolve target info
        target_node = self._graph.nodes.get(selected.scored_path.path.target)
        target_type = target_node.properties.get("artifact_type", "unknown") if target_node else "unknown"
        target_label = target_node.label if target_node else "unknown"

        # Estimate exploit chain steps (edges that are exploit/credential_usage/privesc)
        actionable_edges = [
            e for e in selected.scored_path.path.edges
            if e in ("exploit", "credential_usage", "lateral_movement", "privilege_escalation")
        ]
        estimated_steps = max(len(actionable_edges), 1)

        strategy = OffensiveStrategy(
            scan_id=self._graph.scan_id,
            selected_path=selected,
            all_ranked=ranked[:max_candidates],
            target_type=target_type,
            target_label=target_label,
            estimated_steps=estimated_steps,
        )

        logger.info(
            "Strategy selected: rank=1 score=%.2f target=%s steps=%d candidates=%d",
            selected.offensive_score, target_type, estimated_steps, len(ranked),
        )
        return strategy

    def _rank_paths(self, scored_paths: list[ScoredPath]) -> list[RankedPath]:
        """Rank paths by offensive impact."""
        ranked: list[RankedPath] = []

        for sp in scored_paths:
            offensive_score = self._compute_offensive_score(sp)
            rationale = self._generate_rationale(sp, offensive_score)

            ranked.append(RankedPath(
                scored_path=sp,
                offensive_score=round(offensive_score, 2),
                rank=0,  # assigned below
                rationale=rationale,
            ))

        # Sort by offensive score descending
        ranked.sort(key=lambda r: r.offensive_score, reverse=True)

        # Assign ranks
        for i, r in enumerate(ranked):
            r.rank = i + 1

        return ranked

    def _compute_offensive_score(self, sp: ScoredPath) -> float:
        """Compute offensive priority score for a path."""
        path = sp.path

        # 1 — Risk score component (normalized to 0-10)
        risk_component = sp.total_score

        # 2 — Privilege depth: how valuable is the target?
        target_node = self._graph.nodes.get(path.target)
        target_atype = target_node.properties.get("artifact_type", "") if target_node else ""
        priv_component = _HIGH_VALUE_TARGETS.get(target_atype, 0.5) * 10

        # 3 — Path efficiency: shorter actionable paths score higher
        if path.depth <= 3:
            efficiency = 10.0
        elif path.depth <= 5:
            efficiency = 8.0
        elif path.depth <= 8:
            efficiency = 5.0
        else:
            efficiency = 3.0

        # 4 — Verified exploit availability
        has_verified = any(
            self._graph.nodes.get(nid) and
            self._graph.nodes[nid].properties.get("artifact_type") in (
                "verified_impact", "database_access", "shell_access",
            )
            for nid in path.nodes
        )
        has_exploit_edge = any(e == "exploit" for e in path.edges)
        exploit_component = 10.0 if has_verified else (7.0 if has_exploit_edge else 3.0)

        # Weighted combination
        score = (
            risk_component * _RANK_WEIGHTS["risk_score"]
            + priv_component * _RANK_WEIGHTS["privilege_depth"]
            + efficiency * _RANK_WEIGHTS["path_efficiency"]
            + exploit_component * _RANK_WEIGHTS["exploit_verified"]
        )

        return min(10.0, max(0.0, score))

    def _generate_rationale(self, sp: ScoredPath, score: float) -> str:
        """Generate human-readable rationale for the ranking."""
        path = sp.path
        target_node = self._graph.nodes.get(path.target)
        target_label = target_node.label if target_node else "unknown"

        parts = [f"Target: {target_label}"]
        parts.append(f"Risk: {sp.risk_level}")
        parts.append(f"Depth: {path.depth} steps")

        if any(e == "exploit" for e in path.edges):
            parts.append("Has exploit edge")
        if any(e == "privilege_escalation" for e in path.edges):
            parts.append("Includes privilege escalation")

        return " | ".join(parts)
