"""Scan schemas — CRUD contracts, status/priority/type enums."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

__all__ = [
    "ScanType",
    "ScanStatus",
    "SCAN_TERMINAL_STATES",
    "ScanPriority",
    "ScanCreate",
    "ScanBatchCreate",
    "MultiAssetScanCreate",
    "MultiAssetScanFailure",
    "MultiAssetScanResponse",
    "ScanRetestCreate",
    "ScanUpdate",
    "ScanResponse",
]


class ScanType(str, Enum):
    recon = "recon"
    vuln = "vuln"
    full = "full"
    exploit_verify = "exploit_verify"


class ScanStatus(str, Enum):
    """Matches the MOD-01.5 revised state machine (14 states)."""

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
    cancelled = "cancelled"


# Terminal states — once a scan reaches one of these, quota is decremented.
SCAN_TERMINAL_STATES = frozenset(
    {ScanStatus.completed, ScanStatus.failed, ScanStatus.rejected, ScanStatus.cancelled}
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
    scheduled_at: datetime | None = Field(
        default=None,
        description="Optional future UTC timestamp for deferred scan start.",
    )
    config: dict | None = Field(
        default=None,
        description="Profile overrides: rate_limit, tool selection, etc.",
    )


class ScanRetestCreate(BaseModel):
    priority: ScanPriority | None = None
    config_overrides: dict | None = Field(
        default=None,
        description="Optional config overrides merged into the retest scan configuration.",
    )


class ScanBatchCreate(BaseModel):
    scan_type: ScanType
    priority: ScanPriority = ScanPriority.normal
    scheduled_at: datetime | None = Field(
        default=None,
        description="Optional future UTC timestamp for deferred batch scan starts.",
    )
    config: dict | None = Field(
        default=None,
        description="Profile overrides applied to every scan in the batch.",
    )


class MultiAssetScanCreate(ScanBatchCreate):
    asset_ids: list[UUID] | None = Field(
        default=None,
        min_length=1,
        description="Explicit active asset IDs to scan.",
    )
    asset_group_id: UUID | None = Field(
        default=None,
        description="Reusable asset-group selector for the batch.",
    )

    @model_validator(mode="after")
    def _validate_target_selector(self) -> "MultiAssetScanCreate":
        has_asset_ids = bool(self.asset_ids)
        has_group_id = self.asset_group_id is not None
        if has_asset_ids == has_group_id:
            raise ValueError("Provide exactly one of asset_ids or asset_group_id")
        return self


class MultiAssetScanFailure(BaseModel):
    asset_id: UUID
    asset_name: str
    reason: str


class MultiAssetScanResponse(BaseModel):
    batch_request_id: str
    asset_group_id: UUID | None = None
    requested_asset_count: int
    created_count: int
    failed_count: int
    scans: list["ScanResponse"]
    failures: list[MultiAssetScanFailure]


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
    scheduled_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    result_summary: dict | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
