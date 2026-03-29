"""Schemas for a durable frontend-visible Pentra Agent transcript."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


AgentTranscriptKind = Literal[
    "capability_advisory",
    "planner_effect",
    "ai_strategy",
    "ai_reasoning",
    "timeline_event",
]

AgentFallbackStatus = Literal["healthy", "fallback", "error", "deterministic", "unknown"]


class AgentTranscriptEntryResponse(BaseModel):
    id: str
    timestamp: datetime
    kind: AgentTranscriptKind
    pack_key: str | None = None
    provider: str | None = None
    model: str | None = None
    transport: str | None = None
    fallback_status: AgentFallbackStatus = "unknown"
    summary: str = ""
    raw_payload: dict[str, Any] | list[Any] | None = None
    artifact_ref: str | None = None


class AgentTranscriptResponse(BaseModel):
    scan_id: UUID
    generated_at: datetime
    entries: list[AgentTranscriptEntryResponse] = Field(default_factory=list)
