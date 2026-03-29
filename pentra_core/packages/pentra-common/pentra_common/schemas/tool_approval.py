"""Schemas for mid-scan approval of approval-gated tools."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


ToolApprovalDisposition = Literal["approved", "already_approved", "requeued", "skipped", "error"]


class ToolApprovalRequest(BaseModel):
    tools: list[str] = Field(default_factory=list, min_length=1)


class ToolApprovalResult(BaseModel):
    tool: str
    disposition: ToolApprovalDisposition
    message: str = ""
    node_id: UUID | None = None
    job_id: UUID | None = None


class ToolApprovalResponse(BaseModel):
    scan_id: UUID
    approved_tools: list[str] = Field(default_factory=list)
    generated_at: datetime
    results: list[ToolApprovalResult] = Field(default_factory=list)
