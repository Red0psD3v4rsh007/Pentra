"""Schemas for report delivery and issue-tracker integrations."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, Field, model_validator


class VerificationPipelineQueueItem(BaseModel):
    finding_id: UUID
    title: str
    vulnerability_type: str
    target: str
    route_group: str | None = None
    severity: str
    verification_state: str | None = None
    truth_state: str
    queue_state: Literal[
        "verified",
        "reproduced",
        "queued",
        "needs_evidence",
        "rejected",
        "expired",
    ]
    readiness_reason: str
    required_actions: list[str] = Field(default_factory=list)
    provenance_complete: bool = False
    replayable: bool = False
    evidence_reference_count: int = 0
    raw_evidence_present: bool = False
    scan_job_bound: bool = False


class VerificationPipelineTypeSummary(BaseModel):
    vulnerability_type: str
    total_findings: int = 0
    verified: int = 0
    reproduced: int = 0
    queued: int = 0
    needs_evidence: int = 0
    rejected: int = 0
    expired: int = 0
    highest_severity: str = "info"
    verified_share: float = 0.0
    proof_ready_share: float = 0.0


class VerificationPipelineSummary(BaseModel):
    profile_id: str | None = None
    scan_type: str
    overall: dict[str, int | float] = Field(default_factory=dict)
    by_type: list[VerificationPipelineTypeSummary] = Field(default_factory=list)
    queue: list[VerificationPipelineQueueItem] = Field(default_factory=list)


class ScanReportNotificationRequest(BaseModel):
    channel: Literal["webhook", "slack"] = "webhook"
    destination_url: AnyHttpUrl
    top_findings_limit: int = Field(default=5, ge=1, le=20)
    include_markdown: bool = False
    include_html: bool = False
    custom_headers: dict[str, str] = Field(default_factory=dict)
    authorization_header: str | None = None


class ScanReportNotificationResponse(BaseModel):
    scan_id: UUID
    channel: Literal["webhook", "slack"]
    delivered_at: datetime
    destination_host: str
    payload_kind: str
    status_code: int
    summary: str
    severity_counts: dict[str, int] = Field(default_factory=dict)
    verification_counts: dict[str, int] = Field(default_factory=dict)
    top_finding_count: int = 0


class ScanIssueExportRequest(BaseModel):
    provider: Literal["github", "jira"]
    mode: Literal["preview", "deliver"] = "preview"
    minimum_severity: Literal["critical", "high", "medium", "low", "info"] = "high"
    verified_only: bool = True
    max_issues: int = Field(default=10, ge=1, le=50)
    destination_url: AnyHttpUrl | None = None
    base_url: AnyHttpUrl | None = None
    repository: str | None = None
    project_key: str | None = None
    custom_headers: dict[str, str] = Field(default_factory=dict)
    authorization_header: str | None = None

    @model_validator(mode="after")
    def _validate_delivery_requirements(self) -> "ScanIssueExportRequest":
        if self.mode != "deliver":
            return self

        if self.provider == "github":
            if self.destination_url is None and not self.repository:
                raise ValueError(
                    "GitHub delivery requires either destination_url or repository"
                )
            return self

        if not self.project_key:
            raise ValueError("Jira delivery requires project_key")
        if self.destination_url is None and self.base_url is None:
            raise ValueError(
                "Jira delivery requires either destination_url or base_url"
            )
        return self


class ScanIssueTicketResponse(BaseModel):
    finding_id: UUID
    fingerprint: str
    title: str
    target: str
    severity: str
    verification_state: str
    labels: list[str] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)
    delivery_status: Literal["preview", "delivered"]
    status_code: int | None = None


class ScanIssueExportResponse(BaseModel):
    scan_id: UUID
    provider: Literal["github", "jira"]
    mode: Literal["preview", "deliver"]
    generated_at: datetime
    destination_host: str | None = None
    selected_count: int = 0
    delivered_count: int = 0
    applied_filters: dict[str, Any] = Field(default_factory=dict)
    tickets: list[ScanIssueTicketResponse] = Field(default_factory=list)
