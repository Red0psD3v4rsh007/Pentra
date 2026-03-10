"""Strategy refiner — generates refined exploit strategies from feedback hints.

MOD-11.7: Takes refinement hints from the feedback analyzer and uses
the PayloadMutator to generate improved payload variants targeting
the specific bypass technique suggested by each hint.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.exploit_feedback_analyzer import FeedbackAnalysis, RefinementHint
from app.engine.payload_mutator import PayloadMutator, MutatedPayload

logger = logging.getLogger(__name__)


@dataclass
class RefinedStrategy:
    """A refined exploit strategy with improved payloads."""

    strategy_id: str
    payload_class: str
    hint_type: str
    original_payload: str
    refined_payloads: list[MutatedPayload] = field(default_factory=list)
    attempt_number: int = 1

    def to_dict(self) -> dict:
        return {
            "strategy_id": self.strategy_id,
            "payload_class": self.payload_class,
            "hint_type": self.hint_type,
            "refined_count": len(self.refined_payloads),
            "attempt": self.attempt_number,
        }


class StrategyRefiner:
    """Generates refined exploit strategies from feedback hints.

    Usage::

        refiner = StrategyRefiner()
        strategies = refiner.refine(feedback)
    """

    def __init__(self, mutator: PayloadMutator | None = None) -> None:
        self._mutator = mutator or PayloadMutator()

    def refine(
        self,
        feedback: FeedbackAnalysis,
        *,
        max_payloads_per_hint: int = 5,
    ) -> list[RefinedStrategy]:
        """Generate refined strategies from feedback analysis."""
        if not feedback.should_refine:
            return []

        strategies: list[RefinedStrategy] = []

        for hint in feedback.hints:
            refined = self._refine_from_hint(
                hint=hint,
                original_payload=feedback.original_payload,
                payload_class=feedback.payload_class,
                attempt=feedback.attempt_number,
                max_payloads=max_payloads_per_hint,
            )
            if refined:
                strategies.append(refined)

        logger.info(
            "StrategyRefiner: %d strategies from %d hints (attempt %d)",
            len(strategies), len(feedback.hints), feedback.attempt_number,
        )
        return strategies

    def _refine_from_hint(
        self,
        *,
        hint: RefinementHint,
        original_payload: str,
        payload_class: str,
        attempt: int,
        max_payloads: int,
    ) -> RefinedStrategy | None:
        """Generate a refined strategy from a single hint."""
        refined_payloads: list[MutatedPayload] = []

        for mutation_name in hint.suggested_mutations[:max_payloads]:
            mutated_text = self._mutator._apply_mutation(original_payload, mutation_name)
            if mutated_text == original_payload:
                # Try encoding instead
                mutated_text = self._mutator._apply_encoding(original_payload, mutation_name)
            if mutated_text != original_payload:
                refined_payloads.append(MutatedPayload(
                    original=original_payload,
                    mutated=mutated_text,
                    mutation_applied=mutation_name,
                    payload_class=payload_class,
                ))

        if not refined_payloads:
            return None

        return RefinedStrategy(
            strategy_id=f"refine:{hint.hint_type}:{payload_class}:a{attempt + 1}",
            payload_class=payload_class,
            hint_type=hint.hint_type,
            original_payload=original_payload,
            refined_payloads=refined_payloads,
            attempt_number=attempt + 1,
        )
