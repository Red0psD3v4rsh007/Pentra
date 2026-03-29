"""Schemas for replayable job command sessions."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from pentra_common.execution_truth import ToolPolicyState
from pentra_common.schemas.canonical_command import CanonicalCommandRecord
from pentra_common.schemas.scan_stream import CommandRuntimeStage


JobSessionChannel = Literal["command", "stdout", "stderr", "system"]


class JobSessionFrameResponse(BaseModel):
    channel: JobSessionChannel
    chunk_seq: int
    chunk_text: str = ""
    timestamp: datetime | None = None
    artifact_ref: str | None = None


class JobSessionResponse(BaseModel):
    scan_id: UUID
    job_id: UUID
    node_id: UUID | None = None
    tool: str
    status: str
    policy_state: ToolPolicyState
    execution_provenance: str | None = None
    execution_reason: str | None = None
    execution_class: str | None = None
    runtime_stage: CommandRuntimeStage | None = None
    last_chunk_at: datetime | None = None
    stream_complete: bool = False
    started_at: datetime | None = None
    completed_at: datetime | None = None
    exit_code: int | None = None
    command: list[str] = Field(default_factory=list)
    display_command: str = ""
    tool_binary: str | None = None
    container_image: str | None = None
    entrypoint: list[str] = Field(default_factory=list)
    working_dir: str | None = None
    canonical_command: CanonicalCommandRecord | None = None
    command_artifact_ref: str | None = None
    full_stdout_artifact_ref: str | None = None
    full_stderr_artifact_ref: str | None = None
    session_artifact_ref: str | None = None
    frames: list[JobSessionFrameResponse] = Field(default_factory=list)
