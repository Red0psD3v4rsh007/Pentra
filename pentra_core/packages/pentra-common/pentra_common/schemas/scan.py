"""Scan schemas — CRUD contracts, status/priority/type enums."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field

__all__ = [
    "ScanType",
    "ScanStatus",
    "SCAN_TERMINAL_STATES",
    "ScanPriority",
    "ScanCreate",
    "ScanUpdate",
    "ScanResponse",
]


class ScanType(str, Enum):
    recon = "recon"
    vuln = "vuln"
    full = "full"
    exploit_verify = "exploit_verify"


class ScanStatus(str, Enum):
    """Matches the MOD-01.5 revised state machine (13 states)."""

    queued = "queued"
    priority_queued = "priority_queued"
    validating = "validating"
    running = "running"
    partial_success = "partial_success"
    paused = "paused"
    analyzing = "analyzing"
    ai_queued = "ai_queued"
    reporting = "reporting"
    completed = "completed"
    failed = "failed"
    rejected = "rejected"
    checkpointed = "checkpointed"


# Terminal states — once a scan reaches one of these, quota is decremented.
SCAN_TERMINAL_STATES = frozenset(
    {ScanStatus.completed, ScanStatus.failed, ScanStatus.rejected}
)


class ScanPriority(str, Enum):
    """Maps to priority queue tiers (P0–P3)."""

    critical = "critical"   # P0 — on-demand, incident response
    high = "high"           # P1 — scheduled-daily
    normal = "normal"       # P2 — scheduled-weekly
    low = "low"             # P3 — continuous monitoring


class ScanCreate(BaseModel):
    asset_id: UUID
    scan_type: ScanType
    priority: ScanPriority = ScanPriority.normal
    config: dict | None = Field(
        default=None,
        description="Profile overrides: rate_limit, tool selection, etc.",
    )


class ScanUpdate(BaseModel):
    """Used internally by orchestrator to update scan state."""

    status: ScanStatus | None = None
    progress: int | None = Field(default=None, ge=0, le=100)
    error_message: str | None = None
    result_summary: dict | None = None


class ScanResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    asset_id: UUID
    scan_type: ScanType
    status: ScanStatus
    priority: ScanPriority
    progress: int
    config: dict
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    result_summary: dict | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
