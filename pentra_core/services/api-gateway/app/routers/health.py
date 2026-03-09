"""Health and readiness probe endpoints.

These endpoints are public (no auth required) and are used by
Kubernetes liveness and readiness probes.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from sqlalchemy import text as sa_text

from pentra_common.db.session import async_engine
from pentra_common.schemas import HealthResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


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
    """Checks database connectivity — returns 200 if ready, 503 if degraded."""
    services: dict[str, str] = {}

    # Check PostgreSQL
    try:
        async with async_engine.connect() as conn:
            await conn.execute(sa_text("SELECT 1"))
        services["db"] = "ok"
    except Exception:
        logger.warning("Database readiness check failed", exc_info=True)
        services["db"] = "unavailable"

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
