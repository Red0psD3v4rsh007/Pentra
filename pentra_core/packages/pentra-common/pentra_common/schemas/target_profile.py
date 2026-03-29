"""Shared target-profile schemas for Phase 3 capability planning."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator


TargetProfileKey = Literal[
    "spa_rest_api",
    "traditional_server_rendered",
    "graphql_heavy_application",
    "auth_heavy_admin_portal",
    "workflow_heavy_commerce",
    "upload_parser_heavy",
]


class TargetProfileDefinition(BaseModel):
    key: TargetProfileKey
    name: str
    description: str
    route_indicators: list[str] = Field(default_factory=list)
    asset_indicators: list[str] = Field(default_factory=list)
    technology_indicators: list[str] = Field(default_factory=list)
    auth_expectations: list[str] = Field(default_factory=list)
    workflow_state_keys: list[str] = Field(default_factory=list)
    likely_challenge_family_keys: list[str] = Field(default_factory=list)
    preferred_capability_pack_keys: list[str] = Field(default_factory=list)
    planner_bias_rules: list[str] = Field(default_factory=list)
    benchmark_target_keys: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_profile(self) -> "TargetProfileDefinition":
        if not self.route_indicators and not self.asset_indicators and not self.technology_indicators:
            raise ValueError(f"Target profile '{self.key}' must define at least one indicator")
        if not self.preferred_capability_pack_keys:
            raise ValueError(f"Target profile '{self.key}' must define preferred_capability_pack_keys")
        if not self.planner_bias_rules:
            raise ValueError(f"Target profile '{self.key}' must define planner_bias_rules")
        return self


class TargetProfileCatalog(BaseModel):
    version: int = 1
    program: str
    phase: int = 3
    generated_at: datetime
    target_profiles: list[TargetProfileDefinition] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_catalog(self) -> "TargetProfileCatalog":
        if not self.target_profiles:
            raise ValueError("Target profile catalog must define target_profiles")
        return self


class TargetProfileHypothesis(BaseModel):
    key: TargetProfileKey
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    preferred_capability_pack_keys: list[str] = Field(default_factory=list)
    planner_bias_rules: list[str] = Field(default_factory=list)
    benchmark_target_keys: list[str] = Field(default_factory=list)

