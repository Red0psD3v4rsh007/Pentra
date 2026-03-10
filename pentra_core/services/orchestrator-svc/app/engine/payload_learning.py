"""Payload learning — tracks payload variant effectiveness.

MOD-13: Monitors payload type effectiveness, mutation strategy
success rates, and false positive rates to prioritize high-success
variants in future payload generation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.learning_store import LearningStore

logger = logging.getLogger(__name__)


@dataclass
class PayloadScore:
    """Effectiveness score for a payload type + mutation combination."""

    payload_type: str
    mutation: str
    success_rate: float
    false_positive_rate: float
    total_attempts: int
    effectiveness: float     # combined score

    def to_dict(self) -> dict:
        return {
            "type": self.payload_type, "mutation": self.mutation,
            "success_rate": round(self.success_rate, 3),
            "fp_rate": round(self.false_positive_rate, 3),
            "effectiveness": round(self.effectiveness, 3),
        }


class PayloadLearning:
    """Tracks and scores payload variant effectiveness.

    Usage::

        learner = PayloadLearning(store)
        scores = learner.compute_scores()
    """

    def __init__(self, store: LearningStore) -> None:
        self._store = store

    def compute_scores(self) -> list[PayloadScore]:
        """Compute effectiveness for all payload type + mutation combos."""
        groups: dict[str, list[dict]] = {}
        for rec in self._store.get_payload_records():
            key = f"{rec['payload_type']}:{rec['mutation']}"
            groups.setdefault(key, []).append(rec)

        scores: list[PayloadScore] = []
        for key, records in groups.items():
            payload_type, mutation = key.split(":", 1)
            total = len(records)
            successes = sum(1 for r in records if r["success"])
            fps = sum(1 for r in records if r.get("false_positive", False))
            success_rate = successes / total if total > 0 else 0
            fp_rate = fps / total if total > 0 else 0
            effectiveness = success_rate * (1 - fp_rate)

            scores.append(PayloadScore(
                payload_type=payload_type, mutation=mutation,
                success_rate=success_rate, false_positive_rate=fp_rate,
                total_attempts=total, effectiveness=effectiveness,
            ))

        scores.sort(key=lambda s: s.effectiveness, reverse=True)
        logger.info("PayloadLearning: %d combos scored", len(scores))
        return scores

    def get_best_payloads(self, payload_type: str, n: int = 5) -> list[PayloadScore]:
        """Return top mutations for a given payload type."""
        return [s for s in self.compute_scores() if s.payload_type == payload_type][:n]

    def summary(self) -> dict[str, Any]:
        scores = self.compute_scores()
        return {
            "total_combos": len(scores),
            "top_effectiveness": round(scores[0].effectiveness, 3) if scores else 0,
            "types": list({s.payload_type for s in scores}),
        }
