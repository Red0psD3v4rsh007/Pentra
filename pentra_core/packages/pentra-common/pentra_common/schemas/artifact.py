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


class ScanReportResponse(BaseModel):
    scan_id: UUID
    report_id: str
    generated_at: datetime
    executive_summary: str
    severity_counts: dict[str, int] = Field(default_factory=dict)
    vulnerability_count: int = 0
    evidence_count: int = 0
    narrative: dict[str, Any] | None = None
    compliance: list[dict[str, Any]] = Field(default_factory=list)
    top_findings: list[dict[str, Any]] = Field(default_factory=list)
    markdown: str
