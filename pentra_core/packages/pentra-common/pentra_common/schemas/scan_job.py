"""ScanJob schemas — execution unit tracking for the orchestrator."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel


class ScanJobStatus(str, Enum):
    pending = "pending"
    assigned = "assigned"
    running = "running"
    completed = "completed"
    failed = "failed"
    skipped = "skipped"


class ScanJobResponse(BaseModel):
    id: UUID
    scan_id: UUID
    phase: int  # 0–6
    tool: str
    status: ScanJobStatus
    priority: str
    worker_id: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    retry_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanJobUpdate(BaseModel):
    """Used by MOD-04 orchestrator to update job state."""

    status: ScanJobStatus | None = None
    worker_id: str | None = None
    output_ref: str | None = None
    error_message: str | None = None
