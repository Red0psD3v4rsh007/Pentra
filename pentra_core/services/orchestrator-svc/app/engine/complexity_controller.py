"""Complexity controller — enforces depth limits on hypothesis generation.

MOD-12.6: Prevents task explosion by enforcing limits on attack chain
depth, recon expansion depth, refinement retries, and hypotheses per
asset.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.hypothesis_graph import HypothesisGraph, HypothesisNode

logger = logging.getLogger(__name__)


@dataclass
class ComplexityLimits:
    """Configurable complexity limits."""

    max_chain_depth: int = 5
    max_recon_depth: int = 4
    max_refinement_retries: int = 5
    max_hypotheses_per_asset: int = 15
    max_total_pending: int = 200
    max_per_module: int = 50


@dataclass
class ComplexityResult:
    """Result of a complexity enforcement pass."""

    total_checked: int = 0
    depth_pruned: int = 0
    asset_cap_pruned: int = 0
    module_cap_pruned: int = 0
    total_cap_pruned: int = 0

    @property
    def total_pruned(self) -> int:
        return self.depth_pruned + self.asset_cap_pruned + self.module_cap_pruned + self.total_cap_pruned

    def to_dict(self) -> dict:
        return {
            "checked": self.total_checked,
            "depth_pruned": self.depth_pruned,
            "asset_cap_pruned": self.asset_cap_pruned,
            "module_cap_pruned": self.module_cap_pruned,
            "total_cap_pruned": self.total_cap_pruned,
            "total_pruned": self.total_pruned,
        }


class ComplexityController:
    """Enforces complexity limits on hypothesis generation.

    Usage::

        ctrl = ComplexityController()
        result = ctrl.enforce(hypothesis_graph)
    """

    def __init__(self, limits: ComplexityLimits | None = None) -> None:
        self._limits = limits or ComplexityLimits()

    def enforce(self, graph: HypothesisGraph) -> ComplexityResult:
        """Apply all complexity limits."""
        result = ComplexityResult()
        pending = graph.get_pending()
        result.total_checked = len(pending)

        # 1 — Enforce depth limits
        for node in pending:
            if self._exceeds_depth(node):
                graph.reject(node.hypothesis.hypothesis_id, reason="depth_limit_exceeded")
                result.depth_pruned += 1

        # 2 — Enforce per-asset cap
        pending = graph.get_pending()
        by_asset: dict[str, list[HypothesisNode]] = {}
        for node in pending:
            target = node.hypothesis.target_node_id
            by_asset.setdefault(target, []).append(node)

        for asset_id, nodes in by_asset.items():
            if len(nodes) > self._limits.max_hypotheses_per_asset:
                nodes.sort(key=lambda n: n.priority_score, reverse=True)
                for excess in nodes[self._limits.max_hypotheses_per_asset:]:
                    graph.reject(excess.hypothesis.hypothesis_id, reason=f"asset_cap:{asset_id}")
                    result.asset_cap_pruned += 1

        # 3 — Enforce per-module cap
        pending = graph.get_pending()
        by_module: dict[str, list[HypothesisNode]] = {}
        for node in pending:
            by_module.setdefault(node.source_module, []).append(node)

        for module, nodes in by_module.items():
            if len(nodes) > self._limits.max_per_module:
                nodes.sort(key=lambda n: n.priority_score, reverse=True)
                for excess in nodes[self._limits.max_per_module:]:
                    graph.reject(excess.hypothesis.hypothesis_id, reason=f"module_cap:{module}")
                    result.module_cap_pruned += 1

        # 4 — Enforce total pending cap
        pending = graph.get_pending()
        if len(pending) > self._limits.max_total_pending:
            pending.sort(key=lambda n: n.priority_score, reverse=True)
            for excess in pending[self._limits.max_total_pending:]:
                graph.reject(excess.hypothesis.hypothesis_id, reason="total_cap_exceeded")
                result.total_cap_pruned += 1

        logger.info("ComplexityController: pruned %d/%d (depth=%d, asset=%d, module=%d, total=%d)",
                     result.total_pruned, result.total_checked,
                     result.depth_pruned, result.asset_cap_pruned,
                     result.module_cap_pruned, result.total_cap_pruned)
        return result

    def _exceeds_depth(self, node: HypothesisNode) -> bool:
        """Check if hypothesis exceeds depth limits."""
        h = node.hypothesis
        config = h.config

        # Chain depth
        chain_depth = config.get("chain_length", config.get("attempt_number", 0))
        if chain_depth > self._limits.max_chain_depth:
            return True

        # Refinement retries
        if config.get("refinement", False):
            attempt = config.get("attempt_number", 1)
            if attempt > self._limits.max_refinement_retries:
                return True

        # Recon depth (expansion hypotheses)
        if "expansion" in h.hypothesis_type:
            depth = config.get("depth", 1)
            if depth > self._limits.max_recon_depth:
                return True

        return False
