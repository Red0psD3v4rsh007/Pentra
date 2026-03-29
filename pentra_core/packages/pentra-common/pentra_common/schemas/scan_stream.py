"""Shared scan stream event schemas for the real-time operator channel."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


ScanStreamEventType = Literal[
    "ws.connected",
    "ws.heartbeat",
    "ws.closing",
    "scan.progress",
    "scan.phase",
    "scan.node",
    "scan.job",
    "scan.command",
    "scan.advisory",
    "scan.status",
    "scan.finding",
]

CommandRuntimeStage = Literal[
    "queued",
    "container_starting",
    "command_resolved",
    "streaming",
    "completed",
    "failed",
    "blocked",
    "stalled",
]


class ScanStreamEvent(BaseModel):
    event_type: ScanStreamEventType
    scan_id: UUID | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    message: str | None = None
    reason: str | None = None
    progress: int | None = None
    phase: str | None = None
    phase_number: int | None = None
    phase_name: str | None = None
    phase_status: str | None = None
    node_id: UUID | None = None
    job_id: UUID | None = None
    tool: str | None = None
    status: str | None = None
    execution_provenance: str | None = None
    execution_reason: str | None = None
    execution_class: str | None = None
    policy_state: str | None = None
    runtime_stage: CommandRuntimeStage | None = None
    last_chunk_at: datetime | None = None
    stream_complete: bool | None = None
    command: list[str] = Field(default_factory=list)
    display_command: str | None = None
    tool_binary: str | None = None
    container_image: str | None = None
    entrypoint: list[str] = Field(default_factory=list)
    working_dir: str | None = None
    channel: str | None = None
    chunk_text: str | None = None
    chunk_seq: int | None = None
    stdout_preview: str | None = None
    stderr_preview: str | None = None
    exit_code: int | None = None
    duration_ms: int | None = None
    artifact_ref: str | None = None
    full_stdout_artifact_ref: str | None = None
    full_stderr_artifact_ref: str | None = None
    command_artifact_ref: str | None = None
    session_artifact_ref: str | None = None
    pack_key: str | None = None
    provider: str | None = None
    model: str | None = None
    transport: str | None = None
    fallback_status: str | None = None
    summary: dict[str, Any] = Field(default_factory=dict)
    old_status: str | None = None
    new_status: str | None = None
    severity: str | None = None
    title: str | None = None
    count: int | None = None
