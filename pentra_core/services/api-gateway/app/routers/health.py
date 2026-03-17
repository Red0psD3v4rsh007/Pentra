"""Health, readiness, and system status endpoints.

These endpoints are public (no auth required) and are used by
Kubernetes liveness/readiness probes and the frontend service
status bar.
"""

from __future__ import annotations

import logging
import os
import time

import httpx
from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text as sa_text

import redis.asyncio as aioredis

from pentra_common.config.settings import get_settings
from pentra_common.db.session import async_engine
from pentra_common.schemas import HealthResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

_STARTUP_TIME = time.monotonic()


class SystemStatusResponse(BaseModel):
    """Response from /api/v1/system/status."""

    status: str  # "ok" | "degraded"
    version: str
    uptime_seconds: int
    services: dict[str, str]  # {"db": "ok", "redis": "ok", "orchestrator": "ok"}


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Liveness probe",
)
async def health() -> HealthResponse:
    """Always returns 200 — confirms the process is alive."""
    return HealthResponse(
        status="ok",
        version="0.1.0",
    )


@router.get(
    "/ready",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Readiness probe",
)
async def ready() -> HealthResponse:
    """Checks database and Redis connectivity — returns 200 if ready, 503 if degraded."""
    services: dict[str, str] = {}

    # Check PostgreSQL
    try:
        async with async_engine.connect() as conn:
            await conn.execute(sa_text("SELECT 1"))
        services["db"] = "ok"
    except Exception:
        logger.warning("Database readiness check failed", exc_info=True)
        services["db"] = "unavailable"

    # Check Redis
    settings = get_settings()
    try:
        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        try:
            await r.ping()
            services["redis"] = "ok"
        finally:
            await r.close()
    except Exception:
        logger.warning("Redis readiness check failed", exc_info=True)
        services["redis"] = "unavailable"

    overall = "ok" if all(v == "ok" for v in services.values()) else "degraded"

    response = HealthResponse(
        status=overall,
        version="0.1.0",
        services=services,
    )

    if overall != "ok":
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=response.model_dump(),
        )

    return response


@router.get(
    "/api/v1/system/status",
    response_model=SystemStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="System status for the frontend service bar",
)
async def system_status(request: Request) -> SystemStatusResponse:
    """Return structured component health for the UI service status bar.

    Checks PostgreSQL, Redis, and orchestrator HTTP health.
    """
    services: dict[str, str] = {}

    # Check PostgreSQL
    try:
        async with async_engine.connect() as conn:
            await conn.execute(sa_text("SELECT 1"))
        services["db"] = "ok"
    except Exception:
        services["db"] = "unavailable"

    # Check Redis via the existing stream publisher on app state
    try:
        publisher = getattr(request.app.state, "stream_publisher", None)
        if publisher and publisher._redis:
            await publisher._redis.ping()
            services["redis"] = "ok"
        else:
            # Fallback: try direct connection
            settings = get_settings()
            r = aioredis.from_url(settings.redis_url, decode_responses=True)
            try:
                await r.ping()
                services["redis"] = "ok"
            finally:
                await r.close()
    except Exception:
        services["redis"] = "unavailable"

    # Check Orchestrator HTTP health
    orchestrator_port = os.environ.get("PENTRA_ORCHESTRATOR_PORT", "8001")
    orchestrator_url = f"http://localhost:{orchestrator_port}/health"
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(orchestrator_url)
            services["orchestrator"] = "ok" if resp.status_code == 200 else "degraded"
    except Exception:
        services["orchestrator"] = "unavailable"

    overall = "ok" if all(v == "ok" for v in services.values()) else "degraded"
    uptime = int(time.monotonic() - _STARTUP_TIME)

    response = SystemStatusResponse(
        status=overall,
        version="0.1.0",
        uptime_seconds=uptime,
        services=services,
    )

    if overall != "ok":
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=response.model_dump(),
        )

    return response
