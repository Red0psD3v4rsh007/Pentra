"""User schemas — response, token."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr


class UserResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    email: str
    full_name: str | None = None
    avatar_url: str | None = None
    is_active: bool
    roles: list[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class UserInvite(BaseModel):
    email: EmailStr
    role: str = "member"


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
