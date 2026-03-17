"""Exploration budget controller — prevents task explosion.

MOD-09: Enforces hard limits on autonomous exploration to prevent
generating millions of tasks from hypothesis-driven testing.

Limits:
  - max_exploration_tasks   — total exploration nodes per scan
  - max_parallel            — concurrent exploration tasks
  - max_depth               — maximum exploration chain depth
"""

from __future__ import annotations

__classification__ = "runtime_optional"

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class BudgetConfig:
    """Exploration budget configuration."""

    max_exploration_tasks: int = 5000
    max_parallel_exploration: int = 20
    max_exploration_depth: int = 6


class ExplorationBudget:
    """Enforces exploration task limits.

    Usage::

        budget = ExplorationBudget()
        if budget.can_create(count=5):
            budget.consume(count=5)
    """

    def __init__(self, config: BudgetConfig | None = None) -> None:
        self._config = config or BudgetConfig()
        self._tasks_created: int = 0
        self._active_tasks: int = 0
        self._max_depth_reached: int = 0

    @property
    def tasks_created(self) -> int:
        return self._tasks_created

    @property
    def active_tasks(self) -> int:
        return self._active_tasks

    @property
    def remaining(self) -> int:
        return max(0, self._config.max_exploration_tasks - self._tasks_created)

    @property
    def config(self) -> BudgetConfig:
        return self._config

    def can_create(self, *, count: int = 1, depth: int = 0) -> bool:
        """Check if exploration tasks can be created within budget."""
        if self._tasks_created + count > self._config.max_exploration_tasks:
            logger.warning(
                "Budget exceeded: %d + %d > %d",
                self._tasks_created, count, self._config.max_exploration_tasks,
            )
            return False

        if self._active_tasks + count > self._config.max_parallel_exploration:
            logger.warning("Parallel limit: %d active", self._active_tasks)
            return False

        if depth > self._config.max_exploration_depth:
            logger.warning("Depth limit: %d > %d", depth, self._config.max_exploration_depth)
            return False

        return True

    def consume(self, *, count: int = 1) -> None:
        """Record creation of exploration tasks."""
        self._tasks_created += count
        self._active_tasks += count

    def release(self, *, count: int = 1) -> None:
        """Record completion of exploration tasks."""
        self._active_tasks = max(0, self._active_tasks - count)

    def get_allowed_count(self, requested: int) -> int:
        """Return how many tasks can be created within remaining budget."""
        remaining = self.remaining
        parallel_room = max(0, self._config.max_parallel_exploration - self._active_tasks)
        return min(requested, remaining, parallel_room)

    def get_status(self) -> dict:
        return {
            "tasks_created": self._tasks_created,
            "active_tasks": self._active_tasks,
            "remaining": self.remaining,
            "max_tasks": self._config.max_exploration_tasks,
            "max_parallel": self._config.max_parallel_exploration,
            "max_depth": self._config.max_exploration_depth,
        }
