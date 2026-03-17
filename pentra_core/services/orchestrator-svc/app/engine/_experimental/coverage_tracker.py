"""Coverage tracker — tracks per-asset vulnerability testing coverage.

MOD-12.6: Monitors which vulnerability classes have been tested on
each asset and rejects hypotheses that would produce redundant tests.
"""

from __future__ import annotations

__classification__ = "experimental"

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.hypothesis_graph import HypothesisGraph, HypothesisNode

logger = logging.getLogger(__name__)


@dataclass
class AssetCoverage:
    """Testing coverage for a single asset."""

    asset_id: str
    tested_classes: set[str] = field(default_factory=set)
    tested_tools: set[str] = field(default_factory=set)
    test_count: int = 0

    @property
    def coverage_breadth(self) -> int:
        return len(self.tested_classes)

    def to_dict(self) -> dict:
        return {
            "asset": self.asset_id,
            "classes": len(self.tested_classes),
            "tools": len(self.tested_tools),
            "tests": self.test_count,
        }


@dataclass
class CoverageResult:
    """Result of a coverage pruning pass."""

    total_checked: int = 0
    redundant_pruned: int = 0
    novel_approved: int = 0

    def to_dict(self) -> dict:
        return {
            "checked": self.total_checked,
            "pruned": self.redundant_pruned,
            "novel": self.novel_approved,
        }


class CoverageTracker:
    """Tracks per-asset testing coverage and prunes redundant tests.

    Usage::

        tracker = CoverageTracker()
        result = tracker.prune(hypothesis_graph)
    """

    def __init__(self) -> None:
        self._coverage: dict[str, AssetCoverage] = {}

    def record_test(self, asset_id: str, vuln_class: str, tool: str) -> None:
        """Record that a test was executed on an asset."""
        cov = self._coverage.setdefault(asset_id, AssetCoverage(asset_id=asset_id))
        cov.tested_classes.add(vuln_class)
        cov.tested_tools.add(tool)
        cov.test_count += 1

    def is_covered(self, asset_id: str, vuln_class: str, tool: str) -> bool:
        """Check if this specific test has already been performed."""
        cov = self._coverage.get(asset_id)
        if not cov:
            return False
        return vuln_class in cov.tested_classes and tool in cov.tested_tools

    def get_coverage(self, asset_id: str) -> AssetCoverage | None:
        return self._coverage.get(asset_id)

    def prune(self, graph: HypothesisGraph) -> CoverageResult:
        """Prune hypotheses that test already-covered vulnerability classes."""
        pending = graph.get_pending()
        result = CoverageResult(total_checked=len(pending))

        for node in pending:
            h = node.hypothesis
            vuln_class = h.config.get("vulnerability_class",
                         h.config.get("payload_class",
                         h.config.get("heuristic_name", "")))
            tool = h.tool

            if self.is_covered(h.target_node_id, vuln_class, tool):
                graph.reject(h.hypothesis_id, reason=f"already_covered:{vuln_class}:{tool}")
                result.redundant_pruned += 1
            else:
                node.coverage_score = self._compute_novelty(h.target_node_id, vuln_class)
                result.novel_approved += 1

        logger.info("CoverageTracker: pruned %d/%d redundant hypotheses",
                     result.redundant_pruned, result.total_checked)
        return result

    def _compute_novelty(self, asset_id: str, vuln_class: str) -> float:
        """Compute how novel this test is relative to existing coverage."""
        cov = self._coverage.get(asset_id)
        if not cov:
            return 1.0  # Completely novel
        if vuln_class in cov.tested_classes:
            return 0.2  # Same class but different tool
        return max(0.3, 1.0 - cov.coverage_breadth * 0.1)

    def summary(self) -> dict[str, Any]:
        return {
            "tracked_assets": len(self._coverage),
            "total_tests": sum(c.test_count for c in self._coverage.values()),
            "avg_classes_per_asset": (
                sum(c.coverage_breadth for c in self._coverage.values())
                / max(len(self._coverage), 1)
            ),
        }
