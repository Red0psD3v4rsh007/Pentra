"""Asset schemas — CRUD contracts, type enum."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


class AssetType(str, Enum):
    web_app = "web_app"
    api = "api"
    network = "network"
    repository = "repository"
    cloud = "cloud"


class AssetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    asset_type: AssetType
    target: str = Field(
        ...,
        min_length=1,
        description="URL / IP / CIDR / repo URL / cloud ARN",
    )
    description: str | None = None
    tags: dict[str, str] | None = None


class AssetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    tags: dict[str, str] | None = None


class AssetResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    project_id: UUID
    name: str
    asset_type: AssetType
    target: str
    description: str | None = None
    is_verified: bool
    is_active: bool
    tags: dict[str, str] = {}
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
