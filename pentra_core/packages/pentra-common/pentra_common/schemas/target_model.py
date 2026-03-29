"""Target-model schemas — normalized target understanding for planner and UI use."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


TargetModelRouteOrigin = str


class TargetModelOverviewResponse(BaseModel):
    endpoint_count: int = 0
    authenticated_endpoint_count: int = 0
    api_endpoint_count: int = 0
    route_group_count: int = 0
    workflow_edge_count: int = 0
    technology_count: int = 0
    parameter_count: int = 0
    auth_surface_count: int = 0
    finding_count: int = 0
    source_artifact_types: list[str] = Field(default_factory=list)
    truth_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)


class TargetModelEndpointResponse(BaseModel):
    url: str
    host: str | None = None
    path: str
    route_group: str
    surface: str = "web"
    requires_auth: bool = False
    auth_variants: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    parameter_names: list[str] = Field(default_factory=list)
    hidden_parameter_names: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    finding_count: int = 0
    vulnerability_types: list[str] = Field(default_factory=list)
    truth_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    has_csrf: bool = False
    safe_replay: bool = False
    origin: str = "observed"
    origins: list[str] = Field(default_factory=list)


class TargetModelRouteGroupResponse(BaseModel):
    route_group: str
    endpoint_count: int = 0
    requires_auth: bool = False
    auth_variants: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    parameter_names: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    finding_count: int = 0
    vulnerability_types: list[str] = Field(default_factory=list)
    truth_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    focus_score: int = 0
    origin: str = "observed"
    origins: list[str] = Field(default_factory=list)


class TargetModelTechnologyResponse(BaseModel):
    technology: str
    endpoint_count: int = 0
    route_groups: list[str] = Field(default_factory=list)
    surfaces: list[str] = Field(default_factory=list)


class TargetModelParameterResponse(BaseModel):
    name: str
    locations: list[str] = Field(default_factory=list)
    endpoint_count: int = 0
    route_groups: list[str] = Field(default_factory=list)
    related_vulnerability_types: list[str] = Field(default_factory=list)
    related_truth_states: list[str] = Field(default_factory=list)
    likely_sensitive: bool = False


class TargetModelAuthSurfaceResponse(BaseModel):
    label: str
    auth_state: str
    endpoint_count: int = 0
    route_groups: list[str] = Field(default_factory=list)
    csrf_form_count: int = 0
    safe_replay_count: int = 0


class TargetModelWorkflowEdgeResponse(BaseModel):
    source_url: str
    target_url: str
    action: str
    source_route_group: str
    target_route_group: str
    requires_auth: bool = False


class TargetModelPlannerFocusResponse(BaseModel):
    route_group: str
    objective: str
    reason: str
    requires_auth: bool = False
    focus_score: int = 0
    vulnerability_types: list[str] = Field(default_factory=list)
    parameter_names: list[str] = Field(default_factory=list)


class ScanTargetModelResponse(BaseModel):
    scan_id: UUID
    tenant_id: UUID
    asset_id: UUID
    asset_name: str
    target: str
    generated_at: datetime
    overview: TargetModelOverviewResponse
    endpoints: list[TargetModelEndpointResponse] = Field(default_factory=list)
    route_groups: list[TargetModelRouteGroupResponse] = Field(default_factory=list)
    technologies: list[TargetModelTechnologyResponse] = Field(default_factory=list)
    parameters: list[TargetModelParameterResponse] = Field(default_factory=list)
    auth_surfaces: list[TargetModelAuthSurfaceResponse] = Field(default_factory=list)
    workflows: list[TargetModelWorkflowEdgeResponse] = Field(default_factory=list)
    planner_focus: list[TargetModelPlannerFocusResponse] = Field(default_factory=list)
