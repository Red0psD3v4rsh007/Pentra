"""Shared utility schemas — pagination, error responses, health."""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginationParams(BaseModel):
    """Query parameters for paginated list endpoints."""

    page: int = Field(default=1, ge=1, description="Page number (1-indexed)")
    page_size: int = Field(default=20, ge=1, le=100, description="Items per page")

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard paginated response envelope."""

    items: list[T]
    total: int
    page: int
    page_size: int


class ErrorResponse(BaseModel):
    """Standard error response body."""

    detail: str
    error_code: str | None = None


class HealthResponse(BaseModel):
    """Response from /health and /ready probes."""

    status: str  # "ok" | "degraded"
    version: str
    services: dict[str, str] = {}  # {"db": "ok", "redis": "ok"}
