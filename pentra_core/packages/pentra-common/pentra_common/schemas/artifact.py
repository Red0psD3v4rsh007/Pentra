"""Schemas for normalized artifacts, evidence, graphs, and scan reports."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class ArtifactSummaryResponse(BaseModel):
    id: UUID
    scan_id: UUID
    node_id: UUID | None = None
    artifact_type: str
    tool: str | None = None
    storage_ref: str
    content_type: str
    size_bytes: int | None = None
    checksum: str | None = None
    item_count: int = 0
    finding_count: int = 0
    evidence_count: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    execution_mode: str | None = None
    execution_provenance: str | None = None
    execution_reason: str | None = None
    created_at: datetime


class AttackGraphNodeResponse(BaseModel):
    id: str
    node_type: str
    label: str
    artifact_ref: str
    properties: dict[str, Any] = Field(default_factory=dict)


class AttackGraphEdgeResponse(BaseModel):
    source: str
    target: str
    edge_type: str
    properties: dict[str, Any] = Field(default_factory=dict)


class AttackGraphResponse(BaseModel):
    scan_id: UUID
    tenant_id: UUID
    built_at: datetime | None = None
    node_count: int = 0
    edge_count: int = 0
    path_summary: dict[str, Any] = Field(default_factory=dict)
    scoring_summary: dict[str, Any] = Field(default_factory=dict)
    nodes: list[AttackGraphNodeResponse] = Field(default_factory=list)
    edges: list[AttackGraphEdgeResponse] = Field(default_factory=list)


class ScanTimelineEventResponse(BaseModel):
    id: str
    timestamp: datetime
    event_type: str
    title: str
    details: str | None = None
    status: str | None = None
    phase: int | None = None
    tool: str | None = None
    job_id: UUID | None = None
    node_id: UUID | None = None
    artifact_ref: str | None = None


class EvidenceReferenceResponse(BaseModel):
    id: str
    finding_id: UUID | None = None
    finding_title: str | None = None
    severity: str = "info"
    tool_source: str | None = None
    evidence_type: str
    label: str
    target: str
    content_preview: str
    content: str | None = None
    storage_ref: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanComparisonResponse(BaseModel):
    current_scan_id: UUID
    baseline_scan_id: UUID | None = None
    generated_at: datetime
    baseline_generated_at: datetime | None = None
    summary: str
    counts: dict[str, int] = Field(default_factory=dict)
    severity_delta: dict[str, int] = Field(default_factory=dict)
    verification_delta: dict[str, int] = Field(default_factory=dict)
    new_findings: list[dict[str, Any]] = Field(default_factory=list)
    resolved_findings: list[dict[str, Any]] = Field(default_factory=list)
    escalated_findings: list[dict[str, Any]] = Field(default_factory=list)


class ScanReportResponse(BaseModel):
    scan_id: UUID
    report_id: str
    generated_at: datetime
    executive_summary: str
    severity_counts: dict[str, int] = Field(default_factory=dict)
    verification_counts: dict[str, int] = Field(default_factory=dict)
    execution_summary: dict[str, int] = Field(default_factory=dict)
    vulnerability_count: int = 0
    evidence_count: int = 0
    asset: dict[str, Any] = Field(default_factory=dict)
    narrative: dict[str, Any] | None = None
    compliance: list[dict[str, Any]] = Field(default_factory=list)
    finding_groups: list[dict[str, Any]] = Field(default_factory=list)
    remediation_plan: list[dict[str, Any]] = Field(default_factory=list)
    comparison: dict[str, Any] | None = None
    retest: dict[str, Any] | None = None
    export_formats: list[str] = Field(default_factory=list)
    top_findings: list[dict[str, Any]] = Field(default_factory=list)
    markdown: str


class AIAdvisoryNextStepResponse(BaseModel):
    title: str
    rationale: str
    confidence: int = Field(default=0, ge=0, le=100)


class AIAttackGraphSummaryResponse(BaseModel):
    summary: str
    risk_overview: str
    next_steps: list[AIAdvisoryNextStepResponse] = Field(default_factory=list)
    confidence: int = Field(default=0, ge=0, le=100)


class AIFindingExplanationResponse(BaseModel):
    finding_id: UUID | None = None
    title: str
    why_it_matters: str
    business_impact: str
    exploitability_assessment: str
    triage_priority: str
    next_steps: list[str] = Field(default_factory=list)
    confidence: int = Field(default=0, ge=0, le=100)


class AIReportAdvisoryResponse(BaseModel):
    draft_summary: str
    prioritization_notes: str
    remediation_focus: list[str] = Field(default_factory=list)
    confidence: int = Field(default=0, ge=0, le=100)


class AIReasoningAuditResponse(BaseModel):
    artifact_id: UUID | None = None
    storage_ref: str | None = None
    context_hash: str
    prompt_version: str
    prompt_artifact_type: str = "ai_reasoning"


class ScanAIReasoningResponse(BaseModel):
    scan_id: UUID
    generated_at: datetime
    provider: str
    model: str
    advisory_mode: str = "advisory_only"
    status: str
    fallback_reason: str | None = None
    attack_graph: AIAttackGraphSummaryResponse
    report: AIReportAdvisoryResponse
    findings: list[AIFindingExplanationResponse] = Field(default_factory=list)
    audit: AIReasoningAuditResponse
