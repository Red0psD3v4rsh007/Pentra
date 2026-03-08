"""Tenant schemas — creation, response, quota, tier enum."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


class TenantTier(str, Enum):
    free = "free"
    pro = "pro"
    enterprise = "enterprise"


class TenantCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    slug: str | None = Field(
        default=None,
        max_length=100,
        pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$",
        description="URL-safe slug; auto-generated from name if omitted",
    )
    tier: TenantTier = TenantTier.free


class TenantUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=255)


class TenantResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    tier: TenantTier
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class TenantQuotaResponse(BaseModel):
    max_concurrent_scans: int
    max_daily_scans: int
    max_assets: int
    max_projects: int
    scans_today: int
    active_scans: int

    model_config = {"from_attributes": True}
