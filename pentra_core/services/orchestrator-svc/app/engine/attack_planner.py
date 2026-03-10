"""Attack planner — ranks attack paths by strategic value.

MOD-12: Analyzes attack graph paths and scores them based on exploit
probability, privilege escalation potential, asset criticality, and
chain efficiency to prioritize the most valuable attack vectors.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.attack_graph_builder import AttackGraph, AttackNode
from app.engine.path_enumerator import PathEnumerator, AttackPath

logger = logging.getLogger(__name__)


@dataclass
class RankedPath:
    """An attack path ranked by strategic value."""

    path_id: str
    nodes: list[str]
    labels: list[str]
    score: float
    factors: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "path_id": self.path_id,
            "length": len(self.nodes),
            "score": round(self.score, 3),
            "factors": {k: round(v, 3) for k, v in self.factors.items()},
            "target": self.labels[-1] if self.labels else "",
        }


# ── Scoring weights ──────────────────────────────────────────────

_WEIGHTS = {
    "exploit_probability": 0.30,
    "privilege_potential": 0.25,
    "asset_criticality": 0.20,
    "chain_efficiency": 0.15,
    "novelty": 0.10,
}

# Nodes that indicate high-value targets
_CRITICAL_LABELS = {"admin", "root", "database", "ssh", "rds", "s3", "credentials", "secret", "key"}
_PRIVILEGE_TYPES = {"privilege", "credential", "access_level"}
_EXPLOIT_TYPES = {"vulnerability", "exploit"}


class AttackPlanner:
    """Analyzes and ranks attack graph paths by strategic value.

    Usage::

        planner = AttackPlanner(graph)
        ranked = planner.plan(max_paths=10)
    """

    def __init__(self, graph: AttackGraph) -> None:
        self._graph = graph
        self._enumerator = PathEnumerator(graph)
        self._attempted_paths: set[str] = set()

    def plan(self, *, max_paths: int = 10) -> list[RankedPath]:
        """Enumerate and rank attack paths."""
        raw_paths = self._enumerator.enumerate_paths()

        ranked: list[RankedPath] = []
        for i, path in enumerate(raw_paths):
            node_ids = path.nodes if isinstance(path, AttackPath) else path
            labels = [self._graph.nodes[n].label for n in node_ids if n in self._graph.nodes]
            factors = self._score_path(node_ids, labels)
            total = sum(_WEIGHTS.get(k, 0) * v for k, v in factors.items())
            ranked.append(RankedPath(
                path_id=f"path:{i}",
                nodes=node_ids,
                labels=labels,
                score=total,
                factors=factors,
            ))

        ranked.sort(key=lambda p: p.score, reverse=True)
        result = ranked[:max_paths]
        logger.info("AttackPlanner: ranked %d paths (top score: %.3f)",
                     len(result), result[0].score if result else 0)
        return result

    def mark_attempted(self, path_id: str) -> None:
        self._attempted_paths.add(path_id)

    def _score_path(self, node_ids: list[str], labels: list[str]) -> dict[str, float]:
        factors: dict[str, float] = {}

        # 1 — Exploit probability: more vulns/exploits in path → higher
        exploit_nodes = sum(
            1 for n in node_ids
            if n in self._graph.nodes and self._graph.nodes[n].node_type in _EXPLOIT_TYPES
        )
        total = max(len(node_ids), 1)
        factors["exploit_probability"] = min(1.0, exploit_nodes / max(total * 0.3, 1))

        # 2 — Privilege escalation potential: ends at privilege node
        last_type = self._graph.nodes[node_ids[-1]].node_type if node_ids and node_ids[-1] in self._graph.nodes else ""
        factors["privilege_potential"] = 1.0 if last_type in _PRIVILEGE_TYPES else 0.3

        # 3 — Asset criticality: critical keywords in labels
        crit_count = sum(1 for label in labels if any(k in label.lower() for k in _CRITICAL_LABELS))
        factors["asset_criticality"] = min(1.0, crit_count * 0.4)

        # 4 — Chain efficiency: shorter paths are more reliable
        factors["chain_efficiency"] = max(0.1, 1.0 - (len(node_ids) - 2) * 0.15)

        # 5 — Novelty: not previously attempted
        path_key = ":".join(node_ids)
        factors["novelty"] = 0.0 if path_key in self._attempted_paths else 1.0

        return factors
