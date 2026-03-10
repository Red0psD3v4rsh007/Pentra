"""Hypothesis graph — centralized store for all hypotheses with metadata.

MOD-12.6: Stores hypotheses as nodes in a global graph, tracks
relationships between them, and maintains metadata (confidence,
novelty, coverage, cost, risk impact) for strategic pruning.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.hypothesis_generator import Hypothesis

logger = logging.getLogger(__name__)


@dataclass
class HypothesisNode:
    """A hypothesis stored in the global graph."""

    hypothesis: Hypothesis
    source_module: str          # recon | exploration | heuristic | pattern | payload | stateful | refinement | expansion
    confidence: float = 0.5     # 0.0–1.0
    novelty: float = 1.0        # 1.0 = never seen, decays
    coverage_score: float = 0.0 # how much new coverage this adds
    estimated_cost: float = 1.0 # relative cost to execute
    risk_impact: float = 0.5    # potential risk impact if successful
    approved: bool = False
    rejected: bool = False
    rejection_reason: str = ""

    @property
    def priority_score(self) -> float:
        """Composite priority: high confidence + novelty + impact, low cost."""
        return (
            self.confidence * 0.25
            + self.novelty * 0.20
            + self.coverage_score * 0.20
            + self.risk_impact * 0.20
            - self.estimated_cost * 0.05
        ) + 0.1  # base

    def to_dict(self) -> dict:
        return {
            "id": self.hypothesis.hypothesis_id,
            "source": self.source_module,
            "priority": round(self.priority_score, 3),
            "approved": self.approved,
            "rejected": self.rejected,
        }


@dataclass
class HypothesisRelation:
    """Relationship between hypotheses."""

    source_id: str
    target_id: str
    relation_type: str  # depends_on | conflicts_with | supersedes | refines


class HypothesisGraph:
    """Global hypothesis store and relationship graph.

    Usage::

        graph = HypothesisGraph()
        graph.add(hypothesis, source_module="heuristic")
        approved = graph.get_approved()
    """

    def __init__(self) -> None:
        self._nodes: dict[str, HypothesisNode] = {}
        self._relations: list[HypothesisRelation] = []

    @property
    def total(self) -> int:
        return len(self._nodes)

    @property
    def approved_count(self) -> int:
        return sum(1 for n in self._nodes.values() if n.approved)

    @property
    def rejected_count(self) -> int:
        return sum(1 for n in self._nodes.values() if n.rejected)

    def add(
        self,
        hypothesis: Hypothesis,
        source_module: str,
        *,
        confidence: float = 0.5,
        risk_impact: float = 0.5,
    ) -> HypothesisNode:
        """Add a hypothesis to the graph."""
        node = HypothesisNode(
            hypothesis=hypothesis,
            source_module=source_module,
            confidence=confidence,
            risk_impact=risk_impact,
        )
        self._nodes[hypothesis.hypothesis_id] = node
        return node

    def add_batch(
        self,
        hypotheses: list[Hypothesis],
        source_module: str,
    ) -> list[HypothesisNode]:
        """Add multiple hypotheses."""
        return [self.add(h, source_module) for h in hypotheses]

    def get(self, hypothesis_id: str) -> HypothesisNode | None:
        return self._nodes.get(hypothesis_id)

    def get_all(self) -> list[HypothesisNode]:
        return list(self._nodes.values())

    def get_pending(self) -> list[HypothesisNode]:
        return [n for n in self._nodes.values() if not n.approved and not n.rejected]

    def get_approved(self) -> list[HypothesisNode]:
        return sorted(
            [n for n in self._nodes.values() if n.approved],
            key=lambda n: n.priority_score, reverse=True,
        )

    def approve(self, hypothesis_id: str) -> None:
        node = self._nodes.get(hypothesis_id)
        if node:
            node.approved = True
            node.rejected = False

    def reject(self, hypothesis_id: str, reason: str = "") -> None:
        node = self._nodes.get(hypothesis_id)
        if node:
            node.rejected = True
            node.approved = False
            node.rejection_reason = reason

    def add_relation(self, rel: HypothesisRelation) -> None:
        self._relations.append(rel)

    def get_by_target(self, target_node_id: str) -> list[HypothesisNode]:
        return [n for n in self._nodes.values()
                if n.hypothesis.target_node_id == target_node_id]

    def get_by_module(self, source_module: str) -> list[HypothesisNode]:
        return [n for n in self._nodes.values() if n.source_module == source_module]

    def summary(self) -> dict[str, Any]:
        by_module: dict[str, int] = {}
        for n in self._nodes.values():
            by_module[n.source_module] = by_module.get(n.source_module, 0) + 1
        return {
            "total": self.total,
            "approved": self.approved_count,
            "rejected": self.rejected_count,
            "pending": self.total - self.approved_count - self.rejected_count,
            "by_module": by_module,
        }
