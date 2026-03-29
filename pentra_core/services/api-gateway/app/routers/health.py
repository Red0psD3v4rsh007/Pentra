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

from app.services import ai_reasoning_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

_STARTUP_TIME = time.monotonic()
_LEGACY_WORKER_HEALTH_PORT = 9100
_WORKER_FAMILY_HEALTH_PORTS = {
    "recon": 9101,
    "network": 9102,
    "web": 9103,
    "vuln": 9104,
    "exploit": 9105,
}
_WORKER_FAMILY_HEALTH_ENV_KEYS = {
    "recon": "PENTRA_WORKER_RECON_HEALTH_PORT",
    "network": "PENTRA_WORKER_NETWORK_HEALTH_PORT",
    "web": "PENTRA_WORKER_WEB_HEALTH_PORT",
    "vuln": "PENTRA_WORKER_VULN_HEALTH_PORT",
    "exploit": "PENTRA_WORKER_EXPLOIT_HEALTH_PORT",
}


class SystemStatusResponse(BaseModel):
    """Response from /api/v1/system/status."""

    status: str  # "ok" | "degraded"
    version: str
    uptime_seconds: int
    services: dict[str, str]


def _unique_ints(values: list[int]) -> list[int]:
    unique: list[int] = []
    seen: set[int] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def _configured_family_worker_health_ports() -> list[int]:
    ports: list[int] = []
    for family, env_key in _WORKER_FAMILY_HEALTH_ENV_KEYS.items():
        configured_value = os.environ.get(env_key)
        if configured_value:
            try:
                ports.append(int(configured_value))
            except ValueError:
                logger.warning("Ignoring invalid worker health port for %s: %s", family, configured_value)
    return _unique_ints(ports)


async def _probe_worker_health_ports(ports: list[int]) -> str:
    if not ports:
        return "unavailable"

    had_success = False
    had_failure = False
    async with httpx.AsyncClient(timeout=2.0) as client:
        for port in ports:
            try:
                resp = await client.get(f"http://127.0.0.1:{port}/health")
                if resp.status_code == 200:
                    had_success = True
                else:
                    had_failure = True
            except Exception:
                had_failure = True

    if had_success and not had_failure:
        return "ok"
    if had_success:
        return "degraded"
    return "unavailable"


async def _check_worker_service_status() -> str:
    explicit_port = os.environ.get("WORKER_HEALTH_PORT")
    if explicit_port:
        try:
            return await _probe_worker_health_ports([int(explicit_port)])
        except ValueError:
            logger.warning("Ignoring invalid WORKER_HEALTH_PORT value: %s", explicit_port)

    legacy_status = await _probe_worker_health_ports([_LEGACY_WORKER_HEALTH_PORT])
    if legacy_status == "ok":
        return legacy_status

    family_ports = _configured_family_worker_health_ports() or list(_WORKER_FAMILY_HEALTH_PORTS.values())
    family_status = await _probe_worker_health_ports(family_ports)
    if family_status != "unavailable":
        return family_status
    return legacy_status


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
    services: dict[str, str] = {"api": "ok"}

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

    services["worker"] = await _check_worker_service_status()

    diagnostics = await ai_reasoning_service.get_ai_provider_diagnostics(live=False)
    ai_state = str(diagnostics.get("operator_state") or "configured_but_fallback")
    services["ai"] = {
        "configured_and_healthy": "ok",
        "configured_but_fallback": "degraded",
        "missing_api_key": "unavailable",
        "provider_unreachable": "unavailable",
        "disabled_by_config": "degraded",
    }.get(ai_state, "degraded")
    services["external_target_scanning"] = (
        "ok" if bool(get_settings().allow_external_targets) else "disabled"
    )

    overall = (
        "ok"
        if all(value in {"ok", "disabled"} for value in services.values())
        else "degraded"
    )
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
