"""Historical finding schemas — cross-scan lineage and occurrence views."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


HistoricalFindingStatus = Literal["active", "resolved"]


class HistoricalFindingOccurrenceResponse(BaseModel):
    id: UUID
    scan_id: UUID
    finding_id: UUID | None = None
    severity: str
    verification_state: str | None = None
    source_type: str
    observed_at: datetime


class HistoricalFindingResponse(BaseModel):
    id: UUID
    asset_id: UUID
    lineage_key: str
    fingerprint: str
    title: str
    vulnerability_type: str | None = None
    route_group: str | None = None
    target: str
    latest_severity: str
    latest_verification_state: str | None = None
    latest_source_type: str
    first_seen_scan_id: UUID | None = None
    first_seen_at: datetime
    last_seen_scan_id: UUID | None = None
    last_seen_at: datetime
    latest_finding_id: UUID | None = None
    occurrence_count: int
    status: HistoricalFindingStatus
    recent_occurrences: list[HistoricalFindingOccurrenceResponse] = Field(default_factory=list)

    model_config = {"from_attributes": True}
