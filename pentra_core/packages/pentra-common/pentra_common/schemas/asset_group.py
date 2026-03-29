"""Asset-group schemas for reusable multi-target workflows."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class AssetGroupCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    asset_ids: list[UUID] = Field(
        ...,
        min_length=1,
        description="Active asset IDs belonging to the same project.",
    )


class AssetGroupUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    asset_ids: list[UUID] | None = Field(
        default=None,
        min_length=1,
        description="Replace the group's asset membership when provided.",
    )


class AssetGroupResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    project_id: UUID
    name: str
    description: str | None = None
    is_active: bool
    asset_count: int
    asset_ids: list[UUID]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
