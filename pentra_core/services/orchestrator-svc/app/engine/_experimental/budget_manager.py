"""Strategic budget manager — enforces global task limits.

MOD-12: Manages budgets for exploration, exploitation, reconnaissance,
and refinement to prevent resource exhaustion and ensure balanced
offensive operations.
"""

from __future__ import annotations

__classification__ = "experimental"

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BudgetAllocation:
    """Budget allocation for a specific action category."""

    category: str          # exploit | recon | exploration | refinement
    max_tasks: int
    used_tasks: int = 0

    @property
    def remaining(self) -> int:
        return max(0, self.max_tasks - self.used_tasks)

    @property
    def exhausted(self) -> bool:
        return self.used_tasks >= self.max_tasks

    @property
    def utilization(self) -> float:
        return self.used_tasks / self.max_tasks if self.max_tasks > 0 else 1.0

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "max": self.max_tasks,
            "used": self.used_tasks,
            "remaining": self.remaining,
            "utilization": round(self.utilization, 2),
        }


@dataclass
class BudgetConfig:
    """Configuration for budget allocation."""

    max_exploit_chains: int = 20
    max_recon_tasks: int = 30
    max_exploration_hypotheses: int = 50
    max_refinement_attempts: int = 15
    max_total_tasks: int = 100
    max_concurrent: int = 10


class BudgetManager:
    """Enforces global task limits and allocates budgets.

    Usage::

        mgr = BudgetManager()
        if mgr.can_allocate("exploit"):
            mgr.allocate("exploit")
    """

    def __init__(self, config: BudgetConfig | None = None) -> None:
        self._config = config or BudgetConfig()
        self._allocations: dict[str, BudgetAllocation] = {
            "exploit": BudgetAllocation("exploit", self._config.max_exploit_chains),
            "recon": BudgetAllocation("recon", self._config.max_recon_tasks),
            "exploration": BudgetAllocation("exploration", self._config.max_exploration_hypotheses),
            "refinement": BudgetAllocation("refinement", self._config.max_refinement_attempts),
        }
        self._total_allocated = 0
        self._active_concurrent = 0

    @property
    def total_allocated(self) -> int:
        return self._total_allocated

    @property
    def total_remaining(self) -> int:
        return max(0, self._config.max_total_tasks - self._total_allocated)

    @property
    def budget_exhausted(self) -> bool:
        return self._total_allocated >= self._config.max_total_tasks

    def can_allocate(self, category: str, count: int = 1) -> bool:
        """Check if budget allows allocation."""
        if self._total_allocated + count > self._config.max_total_tasks:
            return False
        alloc = self._allocations.get(category)
        if not alloc:
            return False
        return alloc.used_tasks + count <= alloc.max_tasks

    def allocate(self, category: str, count: int = 1) -> bool:
        """Allocate budget for a task category."""
        if not self.can_allocate(category, count):
            return False
        self._allocations[category].used_tasks += count
        self._total_allocated += count
        return True

    def release(self, category: str, count: int = 1) -> None:
        """Release allocated budget (task completed)."""
        alloc = self._allocations.get(category)
        if alloc:
            alloc.used_tasks = max(0, alloc.used_tasks - count)
            self._total_allocated = max(0, self._total_allocated - count)

    def get_allocation(self, category: str) -> BudgetAllocation | None:
        return self._allocations.get(category)

    def filter_by_budget(self, actions: list) -> list:
        """Filter actions based on available budget."""
        # Map action types to budget categories
        type_to_category = {
            "exploit_chain": "exploit",
            "deeper_recon": "recon",
            "expand_exploration": "exploration",
            "refine_exploit": "refinement",
        }
        filtered = []
        for action in actions:
            action_type = getattr(action, "action_type", "")
            category = type_to_category.get(action_type, "exploration")
            if self.can_allocate(category):
                filtered.append(action)
        return filtered

    def summary(self) -> dict[str, Any]:
        return {
            "total_allocated": self._total_allocated,
            "total_remaining": self.total_remaining,
            "budget_exhausted": self.budget_exhausted,
            "categories": {k: v.to_dict() for k, v in self._allocations.items()},
        }

    def reset(self) -> None:
        """Reset all budgets."""
        for alloc in self._allocations.values():
            alloc.used_tasks = 0
        self._total_allocated = 0
