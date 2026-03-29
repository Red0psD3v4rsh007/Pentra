"""Schemas for truthful persisted command execution records."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from pentra_common.execution_truth import ExecutionClass, ToolPolicyState


CommandChannel = Literal["container", "native", "unknown"]


class CanonicalCommandRecord(BaseModel):
    argv: list[str] = Field(default_factory=list)
    display_command: str = ""
    tool_binary: str | None = None
    container_image: str | None = None
    entrypoint: list[str] = Field(default_factory=list)
    working_dir: str | None = None
    channel: CommandChannel = "unknown"
    execution_class: ExecutionClass = "external_tool"
    policy_state: ToolPolicyState | None = None
