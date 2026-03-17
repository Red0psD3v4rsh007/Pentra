"""Chain learning — records and prioritizes successful attack sequences.

MOD-13: Tracks complete attack chains (e.g. endpoint_discovery →
sql_injection → credential_extraction → ssh_login) and prioritizes
them when similar attack graphs appear in future scans.
"""

from __future__ import annotations

__classification__ = "experimental"

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.learning_store import LearningStore

logger = logging.getLogger(__name__)


@dataclass
class ChainPattern:
    """A learned attack chain pattern with statistics."""

    pattern_id: str
    steps: list[str]
    target_tech: str
    occurrences: int
    success_count: int
    avg_length: float
    priority: float

    def to_dict(self) -> dict:
        return {
            "id": self.pattern_id, "steps": self.steps,
            "tech": self.target_tech, "occurrences": self.occurrences,
            "success_rate": round(self.success_count / max(self.occurrences, 1), 3),
            "priority": round(self.priority, 3),
        }


class ChainLearning:
    """Records and prioritizes attack chain patterns.

    Usage::

        learner = ChainLearning(store)
        patterns = learner.compute_patterns()
    """

    def __init__(self, store: LearningStore) -> None:
        self._store = store

    def compute_patterns(self) -> list[ChainPattern]:
        """Identify recurring chain patterns from telemetry."""
        chains = self._store.get_chains()
        # Group by step signature
        sig_groups: dict[str, list] = {}
        for chain in chains:
            sig = "→".join(chain.steps)
            sig_groups.setdefault(sig, []).append(chain)

        patterns: list[ChainPattern] = []
        for i, (sig, group) in enumerate(sig_groups.items()):
            total = len(group)
            successes = sum(1 for c in group if c.success)
            avg_len = sum(len(c.steps) for c in group) / total
            success_rate = successes / total
            # Priority: success rate × log(occurrences+1) / avg_length
            import math
            priority = success_rate * math.log(total + 1) / max(avg_len, 1)

            patterns.append(ChainPattern(
                pattern_id=f"chain_pattern:{i}",
                steps=group[0].steps,
                target_tech=group[0].target_tech,
                occurrences=total,
                success_count=successes,
                avg_length=avg_len,
                priority=priority,
            ))

        patterns.sort(key=lambda p: p.priority, reverse=True)
        logger.info("ChainLearning: %d patterns from %d chains", len(patterns), len(chains))
        return patterns

    def match_graph(self, available_steps: list[str]) -> list[ChainPattern]:
        """Find chain patterns whose steps are a subset of available_steps."""
        step_set = set(available_steps)
        return [
            p for p in self.compute_patterns()
            if set(p.steps).issubset(step_set)
        ]

    def summary(self) -> dict[str, Any]:
        patterns = self.compute_patterns()
        return {
            "total_patterns": len(patterns),
            "top_priority": round(patterns[0].priority, 3) if patterns else 0,
        }
