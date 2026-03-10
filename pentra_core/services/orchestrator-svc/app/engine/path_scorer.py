"""Path scorer — assigns risk scores to attack paths.

MOD-07: Analyzes each AttackPath and computes a composite risk score
based on multiple factors:

  - CVSS severity of vulnerabilities along the path
  - Exploit verification status
  - Privilege escalation potential
  - Asset criticality
  - Attack path length (shorter = higher risk)

Scores are normalized to 0.0–10.0 scale.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from app.engine.attack_graph_builder import AttackGraph
from app.engine.path_enumerator import AttackPath

logger = logging.getLogger(__name__)


# Score weights (must sum to 1.0)
_WEIGHTS = {
    "severity": 0.30,
    "exploit_verified": 0.25,
    "privilege_level": 0.20,
    "path_efficiency": 0.15,
    "asset_criticality": 0.10,
}

# Impact type → base severity score (0-10)
_IMPACT_SEVERITY: dict[str, float] = {
    "shell_access": 10.0,
    "database_access": 9.0,
    "privilege_escalation": 9.5,
    "credential_leak": 8.0,
    "admin_access": 10.0,
}

# Edge type → risk multiplier
_EDGE_RISK: dict[str, float] = {
    "exploit": 1.0,
    "privilege_escalation": 0.9,
    "credential_usage": 0.7,
    "lateral_movement": 0.8,
    "discovery": 0.3,
}


@dataclass
class ScoredPath:
    """An attack path with a computed risk score."""

    path: AttackPath
    total_score: float         # 0.0–10.0
    severity_score: float
    exploit_score: float
    privilege_score: float
    efficiency_score: float
    criticality_score: float
    risk_level: str            # critical | high | medium | low | info


class PathScorer:
    """Scores and ranks attack paths by risk.

    Usage::

        scorer = PathScorer(graph)
        scored = scorer.score_paths(paths)
    """

    def __init__(self, graph: AttackGraph) -> None:
        self._graph = graph

    def score_paths(self, paths: list[AttackPath]) -> list[ScoredPath]:
        """Score all paths and return sorted by risk (highest first)."""
        scored = [self._score_path(p) for p in paths]
        scored.sort(key=lambda s: s.total_score, reverse=True)

        logger.info(
            "Scored %d paths: %d critical, %d high, %d medium",
            len(scored),
            sum(1 for s in scored if s.risk_level == "critical"),
            sum(1 for s in scored if s.risk_level == "high"),
            sum(1 for s in scored if s.risk_level == "medium"),
        )
        return scored

    def _score_path(self, path: AttackPath) -> ScoredPath:
        """Compute composite risk score for a single path."""

        # 1 — Severity: based on target impact type
        severity = self._severity_score(path)

        # 2 — Exploit verification: are vulnerabilities on this path verified?
        exploit = self._exploit_score(path)

        # 3 — Privilege level: how deep does the attacker get?
        privilege = self._privilege_score(path)

        # 4 — Path efficiency: shorter paths = higher risk
        efficiency = self._efficiency_score(path)

        # 5 — Asset criticality: based on target properties
        criticality = self._criticality_score(path)

        # Weighted composite
        total = (
            severity * _WEIGHTS["severity"]
            + exploit * _WEIGHTS["exploit_verified"]
            + privilege * _WEIGHTS["privilege_level"]
            + efficiency * _WEIGHTS["path_efficiency"]
            + criticality * _WEIGHTS["asset_criticality"]
        )

        # Clamp to 0-10
        total = min(10.0, max(0.0, total))

        return ScoredPath(
            path=path,
            total_score=round(total, 2),
            severity_score=round(severity, 2),
            exploit_score=round(exploit, 2),
            privilege_score=round(privilege, 2),
            efficiency_score=round(efficiency, 2),
            criticality_score=round(criticality, 2),
            risk_level=self._risk_level(total),
        )

    def _severity_score(self, path: AttackPath) -> float:
        """Score based on target impact type."""
        target_node = self._graph.nodes.get(path.target)
        if not target_node:
            return 0.0

        artifact_type = target_node.properties.get("artifact_type", "")
        return _IMPACT_SEVERITY.get(artifact_type, 5.0)

    def _exploit_score(self, path: AttackPath) -> float:
        """Score based on whether exploits along the path are verified."""
        has_exploit_edge = any(e == "exploit" for e in path.edges)
        has_verified = False

        for nid in path.nodes:
            node = self._graph.nodes.get(nid)
            if node and node.properties.get("artifact_type") in (
                "verified_impact", "database_access", "shell_access",
            ):
                has_verified = True
                break

        if has_verified:
            return 10.0
        elif has_exploit_edge:
            return 7.0
        else:
            return 3.0

    def _privilege_score(self, path: AttackPath) -> float:
        """Score based on the privilege level reached."""
        max_priv = 0.0
        for nid in path.nodes:
            node = self._graph.nodes.get(nid)
            if node and node.node_type == "privilege":
                atype = node.properties.get("artifact_type", "")
                priv = _IMPACT_SEVERITY.get(atype, 5.0)
                max_priv = max(max_priv, priv)
        return max_priv

    def _efficiency_score(self, path: AttackPath) -> float:
        """Score inversely proportional to path length."""
        # 2-step path = 10.0, 5-step = 7.0, 10-step = 2.0
        if path.depth <= 2:
            return 10.0
        elif path.depth <= 4:
            return 8.0
        elif path.depth <= 6:
            return 6.0
        elif path.depth <= 8:
            return 4.0
        else:
            return max(1.0, 10.0 - path.depth)

    def _criticality_score(self, path: AttackPath) -> float:
        """Score based on target asset criticality."""
        # Default to moderate criticality
        # In production, this would reference asset_inventory criticality
        edge_risk_sum = sum(_EDGE_RISK.get(e, 0.3) for e in path.edges)
        avg_risk = edge_risk_sum / max(len(path.edges), 1)
        return min(10.0, avg_risk * 10)

    def _risk_level(self, score: float) -> str:
        """Map numeric score to risk level."""
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score >= 2.0:
            return "low"
        else:
            return "info"

    def get_scoring_summary(self, scored_paths: list[ScoredPath]) -> dict:
        """Generate a summary of all scored paths."""
        if not scored_paths:
            return {
                "total_paths": 0,
                "risk_distribution": {},
                "highest_score": 0.0,
            }

        dist: dict[str, int] = {}
        for sp in scored_paths:
            dist[sp.risk_level] = dist.get(sp.risk_level, 0) + 1

        return {
            "total_paths": len(scored_paths),
            "risk_distribution": dist,
            "highest_score": scored_paths[0].total_score,
            "highest_risk_path": {
                "target": scored_paths[0].path.target,
                "depth": scored_paths[0].path.depth,
                "edges": scored_paths[0].path.edges,
            },
        }
