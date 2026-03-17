"""Surface risk scorer — assigns risk scores to discovered assets.

MOD-12.5: Scores each asset in the asset graph based on exposure
level, credential presence, service sensitivity, cross-domain reach,
and relation density to prioritize the riskiest parts of the surface.
"""

from __future__ import annotations

__classification__ = "experimental"

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.asset_graph_builder import AssetGraph, AssetNode

logger = logging.getLogger(__name__)


@dataclass
class AssetRisk:
    """Risk assessment for a single asset."""

    asset_id: str
    asset_label: str
    domain: str
    risk_score: float        # 0.0–10.0
    factors: dict[str, float] = field(default_factory=dict)
    risk_level: str = ""     # critical | high | medium | low | info

    def to_dict(self) -> dict:
        return {
            "asset": self.asset_label,
            "domain": self.domain,
            "score": round(self.risk_score, 2),
            "level": self.risk_level,
        }


# ── Scoring weights ──────────────────────────────────────────────

_WEIGHTS = {
    "exposure": 0.25,
    "credential_proximity": 0.25,
    "service_sensitivity": 0.20,
    "relation_density": 0.15,
    "asset_value": 0.15,
}

# High-value asset labels
_SENSITIVE_KEYWORDS = {
    "admin", "root", "database", "ssh", "rds", "s3", "secret",
    "api_key", "token", "password", "private", "internal",
    "vpn", "ldap", "active_directory", "iam",
}

_EXPOSED_TYPES = {"endpoint", "service", "subdomain"}
_SENSITIVE_SERVICES = {"ssh", "rdp", "ftp", "smb", "telnet", "mysql", "postgres", "redis", "mongodb"}


class SurfaceRiskScorer:
    """Assigns risk scores to assets in the asset graph.

    Usage::

        scorer = SurfaceRiskScorer()
        risks = scorer.score(asset_graph)
    """

    def score(self, graph: AssetGraph) -> list[AssetRisk]:
        """Score all assets in the graph."""
        risks: list[AssetRisk] = []

        # Pre-compute relation counts
        rel_counts: dict[str, int] = {}
        for rel in graph.relations:
            rel_counts[rel.source] = rel_counts.get(rel.source, 0) + 1
            rel_counts[rel.target] = rel_counts.get(rel.target, 0) + 1

        cred_ids = {n.id for n in graph.get_by_type("credential")}
        cred_neighbors = set()
        for rel in graph.relations:
            if rel.source in cred_ids:
                cred_neighbors.add(rel.target)
            if rel.target in cred_ids:
                cred_neighbors.add(rel.source)

        max_rels = max(rel_counts.values(), default=1)

        for node in graph.nodes.values():
            factors = self._score_asset(node, rel_counts, max_rels, cred_ids, cred_neighbors)
            total = sum(_WEIGHTS.get(k, 0) * v for k, v in factors.items()) * 10
            level = self._classify(total)
            risks.append(AssetRisk(
                asset_id=node.id, asset_label=node.label,
                domain=node.domain, risk_score=total,
                factors=factors, risk_level=level,
            ))

        risks.sort(key=lambda r: r.risk_score, reverse=True)
        logger.info("SurfaceRiskScorer: scored %d assets (max: %.1f)",
                     len(risks), risks[0].risk_score if risks else 0)
        return risks

    def top_risks(self, graph: AssetGraph, n: int = 5) -> list[AssetRisk]:
        return self.score(graph)[:n]

    def summary(self, risks: list[AssetRisk]) -> dict[str, Any]:
        levels: dict[str, int] = {}
        for r in risks:
            levels[r.risk_level] = levels.get(r.risk_level, 0) + 1
        return {
            "total_assets": len(risks),
            "avg_score": round(sum(r.risk_score for r in risks) / max(len(risks), 1), 2),
            "max_score": round(max((r.risk_score for r in risks), default=0), 2),
            "levels": levels,
        }

    def _score_asset(
        self, node: AssetNode,
        rel_counts: dict[str, int], max_rels: int,
        cred_ids: set[str], cred_neighbors: set[str],
    ) -> dict[str, float]:
        factors: dict[str, float] = {}

        # 1 — Exposure: externally-reachable asset types
        factors["exposure"] = 0.8 if node.asset_type in _EXPOSED_TYPES else 0.3

        # 2 — Credential proximity: is or neighbors a credential
        if node.id in cred_ids:
            factors["credential_proximity"] = 1.0
        elif node.id in cred_neighbors:
            factors["credential_proximity"] = 0.7
        else:
            factors["credential_proximity"] = 0.1

        # 3 — Service sensitivity
        label_lower = node.label.lower()
        if any(s in label_lower for s in _SENSITIVE_SERVICES):
            factors["service_sensitivity"] = 0.9
        elif node.asset_type == "service":
            factors["service_sensitivity"] = 0.5
        else:
            factors["service_sensitivity"] = 0.2

        # 4 — Relation density: more connections → more attack surface
        factors["relation_density"] = min(1.0, rel_counts.get(node.id, 0) / max(max_rels, 1))

        # 5 — Asset value: sensitive keywords
        value = sum(1 for kw in _SENSITIVE_KEYWORDS if kw in label_lower)
        factors["asset_value"] = min(1.0, value * 0.3)

        return factors

    def _classify(self, score: float) -> str:
        if score >= 8.0:
            return "critical"
        if score >= 6.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score >= 2.0:
            return "low"
        return "info"
