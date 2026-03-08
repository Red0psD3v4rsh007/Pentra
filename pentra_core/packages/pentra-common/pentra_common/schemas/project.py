"""Project schemas — CRUD contracts."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    slug: str | None = Field(
        default=None,
        max_length=100,
        pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$",
        description="URL-safe slug; auto-generated from name if omitted",
    )
    description: str | None = None


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=255)
    description: str | None = None


class ProjectResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    name: str
    slug: str
    description: str | None = None
    is_active: bool
    asset_count: int = 0  # computed at query time
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
