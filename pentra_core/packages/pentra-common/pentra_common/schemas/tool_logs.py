"""Schemas for executed tool command logs and full log retrieval."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from pentra_common.execution_truth import ToolPolicyState
from pentra_common.schemas.canonical_command import CanonicalCommandRecord
from pentra_common.schemas.scan_stream import CommandRuntimeStage


class ToolExecutionLogEntryResponse(BaseModel):
    node_id: UUID
    tool: str
    worker_family: str
    phase_number: int
    phase_name: str
    status: str
    job_id: UUID | None = None
    job_status: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int = 0
    execution_mode: str = "unknown"
    execution_provenance: str = "unknown"
    execution_reason: str | None = None
    execution_class: str | None = None
    policy_state: ToolPolicyState | None = None
    runtime_stage: CommandRuntimeStage | None = None
    last_chunk_at: datetime | None = None
    stream_complete: bool = False
    error_message: str | None = None
    item_count: int = 0
    finding_count: int = 0
    storage_ref: str | None = None
    command: list[str] = Field(default_factory=list)
    display_command: str = ""
    tool_binary: str | None = None
    container_image: str | None = None
    entrypoint: list[str] = Field(default_factory=list)
    working_dir: str | None = None
    canonical_command: CanonicalCommandRecord | None = None
    stdout_preview: str = ""
    stderr_preview: str = ""
    exit_code: int | None = None
    full_stdout_artifact_ref: str | None = None
    full_stderr_artifact_ref: str | None = None
    command_artifact_ref: str | None = None
    session_artifact_ref: str | None = None


class ToolExecutionLogResponse(BaseModel):
    scan_id: UUID
    total: int = 0
    logs: list[ToolExecutionLogEntryResponse] = Field(default_factory=list)


class ToolExecutionLogContentResponse(BaseModel):
    scan_id: UUID
    storage_ref: str
    content_type: Literal["stdout", "stderr", "command"]
    content: str = ""
