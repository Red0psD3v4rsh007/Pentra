"""ScanJob schemas — execution unit tracking for the orchestrator."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel

from pentra_common.execution_truth import ToolPolicyState


class ScanJobStatus(str, Enum):
    queued = "queued"
    pending = "pending"
    scheduled = "scheduled"
    assigned = "assigned"
    running = "running"
    completed = "completed"
    failed = "failed"
    skipped = "skipped"
    blocked = "blocked"


class ScanJobResponse(BaseModel):
    id: UUID
    scan_id: UUID
    node_id: UUID | None = None
    phase: int  # 0–6
    tool: str
    status: ScanJobStatus
    priority: str
    worker_id: str | None = None
    output_ref: str | None = None
    scheduled_at: datetime | None = None
    claimed_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    retry_count: int
    queue_delay_seconds: float | None = None
    claim_to_start_seconds: float | None = None
    execution_duration_seconds: float | None = None
    end_to_end_seconds: float | None = None
    execution_mode: str | None = None
    execution_provenance: str | None = None
    execution_reason: str | None = None
    execution_class: str | None = None
    policy_state: ToolPolicyState | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanJobUpdate(BaseModel):
    """Used by MOD-04 orchestrator to update job state."""

    status: ScanJobStatus | None = None
    worker_id: str | None = None
    output_ref: str | None = None
    error_message: str | None = None
