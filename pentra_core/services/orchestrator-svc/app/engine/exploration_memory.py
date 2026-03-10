"""Exploration memory — tracks executed hypotheses to prevent duplicate tests.

MOD-09: Maintains an in-memory record of explored targets during scan
execution. Does NOT modify database schemas.

Memory key: (hypothesis_type, target_node_id, tool)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class MemoryRecord:
    """Record of an executed exploration hypothesis."""

    hypothesis_type: str
    target_node_id: str
    tool: str
    parameters_tested: list[str]
    timestamp: str
    result: str = "pending"  # pending | success | no_findings


class ExplorationMemory:
    """In-memory deduplication for exploration hypotheses.

    Usage::

        memory = ExplorationMemory()
        if not memory.has_explored(hypothesis):
            memory.record(hypothesis)
    """

    def __init__(self) -> None:
        self._records: dict[str, MemoryRecord] = {}

    def _key(self, hypothesis_type: str, target_node_id: str, tool: str) -> str:
        return f"{hypothesis_type}:{target_node_id}:{tool}"

    def has_explored(
        self,
        *,
        hypothesis_type: str,
        target_node_id: str,
        tool: str,
    ) -> bool:
        """Check if this exact exploration has already been attempted."""
        return self._key(hypothesis_type, target_node_id, tool) in self._records

    def record(
        self,
        *,
        hypothesis_type: str,
        target_node_id: str,
        tool: str,
        parameters_tested: list[str] | None = None,
    ) -> None:
        """Record an exploration attempt."""
        key = self._key(hypothesis_type, target_node_id, tool)
        self._records[key] = MemoryRecord(
            hypothesis_type=hypothesis_type,
            target_node_id=target_node_id,
            tool=tool,
            parameters_tested=parameters_tested or [],
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def mark_result(
        self,
        *,
        hypothesis_type: str,
        target_node_id: str,
        tool: str,
        result: str,
    ) -> None:
        """Update the result of a previously recorded exploration."""
        key = self._key(hypothesis_type, target_node_id, tool)
        if key in self._records:
            self._records[key].result = result

    @property
    def total_explored(self) -> int:
        return len(self._records)

    def get_status(self) -> dict:
        results: dict[str, int] = {}
        for r in self._records.values():
            results[r.result] = results.get(r.result, 0) + 1
        return {
            "total_explored": self.total_explored,
            "results": results,
        }
