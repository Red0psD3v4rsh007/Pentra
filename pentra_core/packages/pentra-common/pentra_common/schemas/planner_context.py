"""Planner-context schemas for frontend-visible runtime inspection."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class ScanPlannerContextResponse(BaseModel):
    scan_id: UUID
    target_profile_hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    capability_pressures: list[dict[str, Any]] = Field(default_factory=list)
    advisory_artifact_refs: list[dict[str, str]] = Field(default_factory=list)
    planner_decision: str | None = None
    strategic_plan: dict[str, Any] | None = None
    tactical_plan: dict[str, Any] | None = None
    planner_effect: dict[str, Any] | None = None
    capability_advisories: list[dict[str, Any]] = Field(default_factory=list)
