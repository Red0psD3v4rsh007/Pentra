"""Target clusterer — clusters targets by technology fingerprint.

MOD-13: Groups scan targets by technology stack (WordPress, React SPA,
Kubernetes API, AWS services, etc.) and stores per-cluster attack
success statistics to enable target-specific offensive strategies.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.learning_store import LearningStore

logger = logging.getLogger(__name__)


@dataclass
class TargetCluster:
    """A cluster of targets sharing technology fingerprint."""

    cluster_id: str
    tech_fingerprint: str
    targets: list[str] = field(default_factory=list)
    exploit_stats: dict[str, dict] = field(default_factory=dict)  # type → {total, successes}

    @property
    def target_count(self) -> int:
        return len(self.targets)

    @property
    def best_exploit(self) -> str:
        if not self.exploit_stats:
            return ""
        return max(self.exploit_stats, key=lambda k: self.exploit_stats[k].get("successes", 0) / max(self.exploit_stats[k].get("total", 1), 1))

    def to_dict(self) -> dict:
        return {
            "id": self.cluster_id, "tech": self.tech_fingerprint,
            "targets": self.target_count,
            "best_exploit": self.best_exploit,
        }


# ── Technology fingerprinting keywords ──────────────────────────

_TECH_PATTERNS: dict[str, list[str]] = {
    "wordpress": ["wordpress", "wp-content", "wp-admin", "wp-login"],
    "react_spa": ["react", "next.js", "gatsby", "_next/", "bundle.js"],
    "kubernetes_api": ["kubernetes", "k8s", "kubectl", "/api/v1", "kube-"],
    "aws_cloud": ["aws", "s3:", "ec2", "lambda", "cloudfront", "amazonaws"],
    "django_app": ["django", "csrfmiddleware", "/admin/", "djdt"],
    "spring_boot": ["spring", "actuator", "/health", "/info", "whitelabel"],
    "php_app": [".php", "phpmyadmin", "php-fpm", "x-powered-by: php"],
    "nodejs_app": ["express", "node.js", "npm", "x-powered-by: express"],
    "api_gateway": ["api-gateway", "kong", "nginx", "envoy", "traefik"],
}


class TargetClusterer:
    """Clusters targets by technology and tracks per-cluster stats.

    Usage::

        clusterer = TargetClusterer(store)
        clusterer.classify("target1", ["wordpress", "wp-admin", "php"])
        clusters = clusterer.get_clusters()
    """

    def __init__(self, store: LearningStore) -> None:
        self._store = store
        self._clusters: dict[str, TargetCluster] = {}
        self._target_to_cluster: dict[str, str] = {}

    @property
    def cluster_count(self) -> int:
        return len(self._clusters)

    def classify(self, target: str, indicators: list[str]) -> str:
        """Classify a target into a technology cluster."""
        tech = self._fingerprint(indicators)
        if tech not in self._clusters:
            self._clusters[tech] = TargetCluster(
                cluster_id=f"cluster:{tech}",
                tech_fingerprint=tech,
            )
        cluster = self._clusters[tech]
        if target not in cluster.targets:
            cluster.targets.append(target)
        self._target_to_cluster[target] = tech
        return tech

    def update_stats(self, target: str, exploit_type: str, success: bool) -> None:
        """Update exploit stats for the target's cluster."""
        tech = self._target_to_cluster.get(target)
        if not tech or tech not in self._clusters:
            return
        cluster = self._clusters[tech]
        stats = cluster.exploit_stats.setdefault(exploit_type, {"total": 0, "successes": 0})
        stats["total"] += 1
        if success:
            stats["successes"] += 1

    def get_clusters(self) -> list[TargetCluster]:
        return sorted(self._clusters.values(), key=lambda c: c.target_count, reverse=True)

    def get_cluster(self, tech: str) -> TargetCluster | None:
        return self._clusters.get(tech)

    def get_recommended_exploits(self, target: str, n: int = 3) -> list[str]:
        """Get recommended exploits for a target based on cluster stats."""
        tech = self._target_to_cluster.get(target)
        if not tech or tech not in self._clusters:
            return []
        cluster = self._clusters[tech]
        ranked = sorted(
            cluster.exploit_stats.items(),
            key=lambda kv: kv[1].get("successes", 0) / max(kv[1].get("total", 1), 1),
            reverse=True,
        )
        return [k for k, _ in ranked[:n]]

    def _fingerprint(self, indicators: list[str]) -> str:
        """Determine technology from indicators."""
        combined = " ".join(indicators).lower()
        best_tech = "generic"
        best_score = 0

        for tech, keywords in _TECH_PATTERNS.items():
            score = sum(1 for kw in keywords if kw in combined)
            if score > best_score:
                best_score = score
                best_tech = tech

        return best_tech

    def summary(self) -> dict[str, Any]:
        return {
            "clusters": self.cluster_count,
            "total_targets": sum(c.target_count for c in self._clusters.values()),
            "techs": list(self._clusters.keys()),
        }
