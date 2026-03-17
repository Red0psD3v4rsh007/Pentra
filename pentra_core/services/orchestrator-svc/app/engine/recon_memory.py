"""Recon coverage tracker — prevents duplicate reconnaissance.

MOD-10: Tracks which recon actions have been executed against which
assets during a scan, preventing redundant work.
"""

from __future__ import annotations

__classification__ = "runtime_optional"

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ReconRecord:
    """Record of a completed recon action."""

    asset_id: str
    action_name: str
    tool: str
    status: str = "completed"  # completed | failed


class ReconMemory:
    """Tracks recon actions to prevent duplicates.

    Usage::

        memory = ReconMemory()
        if not memory.has_explored(asset_id, action_name):
            # execute recon
            memory.record(asset_id, action_name, tool)
    """

    def __init__(self) -> None:
        self._records: dict[str, ReconRecord] = {}  # key → record

    @staticmethod
    def _key(asset_id: str, action_name: str) -> str:
        return f"{asset_id}:{action_name}"

    def has_explored(self, asset_id: str, action_name: str) -> bool:
        """Check if a recon action was already executed on an asset."""
        return self._key(asset_id, action_name) in self._records

    def record(
        self,
        asset_id: str,
        action_name: str,
        tool: str,
        *,
        status: str = "completed",
    ) -> None:
        """Record a recon action execution."""
        key = self._key(asset_id, action_name)
        self._records[key] = ReconRecord(
            asset_id=asset_id,
            action_name=action_name,
            tool=tool,
            status=status,
        )

    def get_coverage(self, asset_id: str) -> list[str]:
        """Get list of recon actions already executed on an asset."""
        prefix = f"{asset_id}:"
        return [
            r.action_name for k, r in self._records.items()
            if k.startswith(prefix)
        ]

    @property
    def total_explored(self) -> int:
        return len(self._records)

    def summary(self) -> dict[str, Any]:
        """Summary of recon coverage."""
        assets: set[str] = set()
        actions: set[str] = set()
        for r in self._records.values():
            assets.add(r.asset_id)
            actions.add(r.action_name)
        return {
            "total_records": len(self._records),
            "unique_assets": len(assets),
            "unique_actions": len(actions),
        }
