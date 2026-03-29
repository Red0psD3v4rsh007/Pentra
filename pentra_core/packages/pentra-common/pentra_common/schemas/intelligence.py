"""Intelligence schemas — cross-scan intelligence summaries for the product UI."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class IntelligenceOverviewResponse(BaseModel):
    total_scans: int
    completed_scans: int
    active_scans: int
    assets_with_history: int
    verified_findings: int
    recurring_patterns: int
    technology_clusters: int
    route_groups: int
    trending_patterns: int = 0
    tracked_assets: int = 0


class IntelligencePatternMatchResponse(BaseModel):
    key: str
    title: str
    vulnerability_type: str | None = None
    route_group: str | None = None
    tool_sources: list[str] = Field(default_factory=list)
    scan_count: int
    finding_count: int
    highest_severity: str
    severity_counts: dict[str, int] = Field(default_factory=dict)
    verification_counts: dict[str, int] = Field(default_factory=dict)
    last_seen: datetime | None = None


class IntelligenceTechnologyClusterResponse(BaseModel):
    technology: str
    asset_count: int
    scan_count: int
    endpoint_count: int
    finding_count: int
    severity_counts: dict[str, int] = Field(default_factory=dict)
    related_assets: list[str] = Field(default_factory=list)
    related_targets: list[str] = Field(default_factory=list)


class IntelligenceRouteGroupResponse(BaseModel):
    route_group: str
    asset_targets: list[str] = Field(default_factory=list)
    scan_count: int
    finding_count: int
    highest_severity: str
    severity_counts: dict[str, int] = Field(default_factory=dict)
    verification_counts: dict[str, int] = Field(default_factory=dict)
    vulnerability_types: list[str] = Field(default_factory=list)


class IntelligenceSurfaceExpansionResponse(BaseModel):
    scan_id: UUID
    asset_id: UUID
    asset_name: str
    target: str
    generated_at: datetime | None = None
    discovered_targets: int
    discovered_forms: int
    technologies: list[str] = Field(default_factory=list)
    artifact_types: list[str] = Field(default_factory=list)


class IntelligenceExploitTrendResponse(BaseModel):
    scan_id: UUID
    asset_name: str
    generated_at: datetime | None = None
    verified: int
    suspected: int
    detected: int


class IntelligenceRetestDeltaResponse(BaseModel):
    scan_id: UUID
    baseline_scan_id: UUID | None = None
    asset_name: str
    target: str
    generated_at: datetime | None = None
    summary: str
    counts: dict[str, int] = Field(default_factory=dict)


class IntelligenceAdvisorySummaryResponse(BaseModel):
    scan_id: UUID
    asset_name: str
    generated_at: datetime | None = None
    advisory_mode: str | None = None
    provider: str | None = None
    model: str | None = None
    draft_summary: str
    prioritization_notes: str | None = None
    remediation_focus: list[str] = Field(default_factory=list)


class IntelligenceTrendingPatternResponse(BaseModel):
    vulnerability_type: str
    recent_count: int
    previous_count: int
    direction: str
    delta: int


class IntelligenceTargetKnowledgeResponse(BaseModel):
    asset_id: UUID
    asset_name: str
    target: str
    scan_count: int
    known_endpoints: int
    known_forms: int
    known_technologies: list[str] = Field(default_factory=list)
    known_auth_surfaces: list[str] = Field(default_factory=list)
    known_vulnerability_types: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class AssetHistoryEntryResponse(BaseModel):
    scan_id: UUID
    scan_type: str
    status: str
    priority: str
    generated_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    severity_counts: dict[str, int] = Field(default_factory=dict)
    verification_counts: dict[str, int] = Field(default_factory=dict)
    total_findings: int = 0
    comparison_summary: str | None = None
    comparison_counts: dict[str, int] = Field(default_factory=dict)
    baseline_scan_id: UUID | None = None


class AssetHistoryResponse(BaseModel):
    asset_id: UUID
    asset_name: str
    target: str
    generated_at: datetime
    total_scans: int
    known_technologies: list[str] = Field(default_factory=list)
    tracked_vulnerability_types: list[str] = Field(default_factory=list)
    entries: list[AssetHistoryEntryResponse] = Field(default_factory=list)


class IntelligenceSummaryResponse(BaseModel):
    generated_at: datetime
    definition: str
    overview: IntelligenceOverviewResponse
    pattern_matches: list[IntelligencePatternMatchResponse] = Field(default_factory=list)
    technology_clusters: list[IntelligenceTechnologyClusterResponse] = Field(default_factory=list)
    route_groups: list[IntelligenceRouteGroupResponse] = Field(default_factory=list)
    surface_expansions: list[IntelligenceSurfaceExpansionResponse] = Field(default_factory=list)
    exploit_trends: list[IntelligenceExploitTrendResponse] = Field(default_factory=list)
    retest_deltas: list[IntelligenceRetestDeltaResponse] = Field(default_factory=list)
    advisory_summaries: list[IntelligenceAdvisorySummaryResponse] = Field(default_factory=list)
    trending_patterns: list[IntelligenceTrendingPatternResponse] = Field(default_factory=list)
    target_knowledge: list[IntelligenceTargetKnowledgeResponse] = Field(default_factory=list)
