"""Scan profile schemas — truthful execution contracts for launchable profiles."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from pentra_common.schemas.scan import ScanPriority, ScanType
from pentra_common.schemas.target_profile import TargetProfileHypothesis

__all__ = [
    "PerformancePolicyResponse",
    "PerformanceToolBudgetResponse",
    "ScanProfileContractResponse",
    "ScanProfilePreflightRequest",
    "ScanProfilePreflightResponse",
]


class PerformanceToolBudgetResponse(BaseModel):
    soft_budget_seconds: int
    hard_timeout_seconds: int
    defer_until_evidence: bool = False


class PerformancePolicyResponse(BaseModel):
    scan_depth_mode: str = "deep"
    phase_barrier_policy: str = "partial_progress"
    tool_budgets: dict[str, PerformanceToolBudgetResponse] = Field(default_factory=dict)
    defer_rules: dict[str, str] = Field(default_factory=dict)


class ScanProfileContractResponse(BaseModel):
    contract_id: str
    scan_type: ScanType
    profile_id: str
    profile_variant: str = "standard"
    name: str
    description: str
    duration: str
    priority: ScanPriority
    execution_mode: str
    target_policy: str
    scope_summary: str
    target_profile_keys: list[str] = Field(default_factory=list)
    requires_preflight: bool = False
    benchmark_inputs_enabled: bool = False
    performance_policy: PerformancePolicyResponse | None = None
    scheduled_tools: list[str]
    live_tools: list[str]
    approval_required_tools: list[str] = Field(default_factory=list)
    conditional_live_tools: list[str]
    derived_tools: list[str]
    unsupported_tools: list[str]
    guardrails: list[str]
    honesty_notes: list[str]
    sellable: bool


class ScanProfilePreflightRequest(BaseModel):
    asset_type: str
    target: str
    contract_id: str
    scan_mode: str = "autonomous"
    methodology: str | None = None
    authorization_acknowledged: bool = False
    approved_live_tools: list[str] = Field(default_factory=list)
    credentials: dict[str, Any] = Field(default_factory=dict)
    repository: dict[str, Any] = Field(default_factory=dict)
    scope: dict[str, Any] = Field(default_factory=dict)


class ScanProfilePreflightResponse(BaseModel):
    contract: ScanProfileContractResponse
    target_context: dict[str, Any] = Field(default_factory=dict)
    target_profile_hypotheses: list[TargetProfileHypothesis] = Field(default_factory=list)
    execution_contract: dict[str, Any] = Field(default_factory=dict)
    scope_authorization: dict[str, Any] = Field(default_factory=dict)
    auth_material: dict[str, Any] = Field(default_factory=dict)
    repository_context: dict[str, Any] = Field(default_factory=dict)
    rate_limit_policy: dict[str, Any] = Field(default_factory=dict)
    safe_replay_policy: dict[str, Any] = Field(default_factory=dict)
    ai_provider_readiness: dict[str, Any] = Field(default_factory=dict)
    benchmark_inputs_enabled: bool = False
    approved_live_tools: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    blocking_issues: list[str] = Field(default_factory=list)
    can_launch: bool = False
