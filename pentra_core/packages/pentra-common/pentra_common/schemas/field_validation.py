"""Schemas for authorized field-validation readiness reporting."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


FieldValidationAssessmentState = Literal[
    "verified",
    "reproduced",
    "detected",
    "needs_evidence",
    "no_findings",
]

FieldValidationOperatingMode = Literal["field_validation", "benchmark", "standard"]


class FieldValidationAssessmentResponse(BaseModel):
    generated_at: datetime
    scan_id: UUID
    asset_id: UUID | None = None
    asset_name: str | None = None
    target: str = ""
    status: str = ""
    profile_id: str | None = None
    profile_variant: str = "standard"
    operating_mode: FieldValidationOperatingMode = "standard"
    benchmark_inputs_enabled: bool = False
    benchmark_inputs_disabled_confirmed: bool = False
    target_profile_guess: str | None = None
    target_profile_hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    selected_capability_packs: list[str] = Field(default_factory=list)
    approved_live_tools: list[str] = Field(default_factory=list)
    approval_required_tools: list[str] = Field(default_factory=list)
    approval_pending_tools: list[str] = Field(default_factory=list)
    tool_policy_states: list[dict[str, str]] = Field(default_factory=list)
    blocked_tools: list[dict[str, str]] = Field(default_factory=list)
    proof_ready_attempts: int = 0
    heuristic_only_attempts: int = 0
    verification_outcomes: dict[str, int] = Field(default_factory=dict)
    evidence_gaps: list[str] = Field(default_factory=list)
    ai_policy_state: str = ""
    ai_provider: str | None = None
    ai_model: str | None = None
    ai_transport: str | None = None
    ai_fallback_active: bool = False
    ai_failure_reason: str | None = None
    assessment_state: FieldValidationAssessmentState = "no_findings"
    summary: str = ""


class FieldValidationSummaryItemResponse(BaseModel):
    scan_id: UUID
    asset_name: str | None = None
    target: str = ""
    status: str = ""
    target_profile_guess: str | None = None
    selected_capability_packs: list[str] = Field(default_factory=list)
    verified: int = 0
    reproduced: int = 0
    detected: int = 0
    needs_evidence: int = 0
    assessment_state: FieldValidationAssessmentState = "no_findings"
    benchmark_inputs_disabled_confirmed: bool = False
    generated_at: datetime


class FieldValidationSummaryResponse(BaseModel):
    generated_at: datetime
    total_scans: int = 0
    by_state: dict[str, int] = Field(default_factory=dict)
    items: list[FieldValidationSummaryItemResponse] = Field(default_factory=list)
