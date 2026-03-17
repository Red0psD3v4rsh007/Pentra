"""Retry planner — schedules refined exploit attempts with budget constraints.

MOD-11.7: Takes refined strategies and converts them into Hypothesis
objects for the exploration pipeline, enforcing max retry counts,
depth limits, and time budgets.
"""

from __future__ import annotations

__classification__ = "experimental"

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.hypothesis_generator import Hypothesis
from app.engine.strategy_refiner import RefinedStrategy

logger = logging.getLogger(__name__)


@dataclass
class RetryBudget:
    """Budget constraints for exploit refinement retries."""

    max_retries: int = 5
    max_depth: int = 3         # max refinement depth (refinement of a refinement)
    max_payloads_total: int = 20
    timeout_per_attempt: int = 600  # seconds

    def allows_retry(self, attempt: int, total_scheduled: int) -> bool:
        return (
            attempt <= self.max_retries
            and total_scheduled < self.max_payloads_total
        )


@dataclass
class RetryPlan:
    """A complete retry plan with scheduled hypotheses."""

    strategies_processed: int = 0
    hypotheses_scheduled: int = 0
    hypotheses_skipped: int = 0
    budget_exhausted: bool = False


class RetryPlanner:
    """Schedules refined exploit attempts as pipeline hypotheses.

    Usage::

        planner = RetryPlanner()
        hypotheses = planner.schedule(strategies)
    """

    def __init__(self, budget: RetryBudget | None = None) -> None:
        self._budget = budget or RetryBudget()
        self._total_scheduled = 0

    @property
    def total_scheduled(self) -> int:
        return self._total_scheduled

    def schedule(
        self,
        strategies: list[RefinedStrategy],
    ) -> tuple[list[Hypothesis], RetryPlan]:
        """Convert refined strategies into scheduled hypotheses."""
        hypotheses: list[Hypothesis] = []
        plan = RetryPlan()

        for strategy in strategies:
            plan.strategies_processed += 1

            if not self._budget.allows_retry(strategy.attempt_number, self._total_scheduled):
                plan.budget_exhausted = True
                plan.hypotheses_skipped += len(strategy.refined_payloads)
                continue

            for payload in strategy.refined_payloads:
                if not self._budget.allows_retry(strategy.attempt_number, self._total_scheduled):
                    plan.budget_exhausted = True
                    plan.hypotheses_skipped += 1
                    continue

                hyp = Hypothesis(
                    hypothesis_id=f"retry:{strategy.strategy_id}:{payload.mutation_applied}",
                    hypothesis_type=f"exploit_refinement_{strategy.hint_type}",
                    target_node_id="",
                    target_label=f"Refined {strategy.payload_class} (attempt {strategy.attempt_number})",
                    description=f"Refined {strategy.payload_class} via {payload.mutation_applied} [{strategy.hint_type}]",
                    tool="custom_poc",
                    worker_family="exploit",
                    config={
                        "payload": payload.mutated,
                        "original_payload": payload.original,
                        "mutation": payload.mutation_applied,
                        "payload_class": strategy.payload_class,
                        "hint_type": strategy.hint_type,
                        "attempt_number": strategy.attempt_number,
                        "refinement": True,
                        "no_persist": True,
                    },
                    required_artifacts=["endpoint"],
                    estimated_complexity=2,
                    timeout_seconds=self._budget.timeout_per_attempt,
                )
                hypotheses.append(hyp)
                self._total_scheduled += 1
                plan.hypotheses_scheduled += 1

        logger.info(
            "RetryPlanner: scheduled %d hypotheses from %d strategies (total: %d)",
            plan.hypotheses_scheduled, plan.strategies_processed, self._total_scheduled,
        )
        return hypotheses, plan

    def reset(self) -> None:
        """Reset the total scheduled counter."""
        self._total_scheduled = 0
