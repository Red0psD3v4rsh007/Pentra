"""Pentra API Gateway — FastAPI application entry point.

This is the **monolith-mode** aggregator: all service routers are
mounted here as sub-applications.  In production (MOD-10+), each
service will be split into its own deployment.

Startup sequence:
  1. Structured logging initialised
  2. Database engine validated (ready probe)
  3. Redis event publisher connected
  4. Middleware stack applied (CORS → Auth → Rate Limit)
  5. Routers mounted under /api/v1
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from pentra_common.config.settings import get_settings
from pentra_common.db.session import async_engine
from pentra_common.events.publisher import EventPublisher
from pentra_common.events.stream_publisher import StreamPublisher
from pentra_common.observability.logging import setup_logging

from app.middleware.cors import configure_cors
from app.middleware.request_context import RequestContextMiddleware
from app.middleware.auth import AuthMiddleware
from app.middleware.rate_limit import RateLimitMiddleware

logger = logging.getLogger(__name__)
settings = get_settings()


# ── Lifespan ─────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup and shutdown hooks."""
    # ── Startup ──────────────────────────────────────────────────
    setup_logging()
    logger.info(
        "Starting Pentra API Gateway [env=%s]",
        settings.app_env,
    )

    # Validate database connectivity
    async with async_engine.connect() as conn:
        await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
    logger.info("Database connection verified")

    # Initialise Redis event publisher (Pub/Sub — backward compat)
    event_publisher = EventPublisher(redis_url=settings.redis_url)
    await event_publisher.connect()
    app.state.event_publisher = event_publisher
    logger.info("Redis event publisher connected (Pub/Sub)")

    # Initialise Redis Streams publisher (durable events for MOD-04)
    stream_publisher = StreamPublisher(redis_url=settings.redis_url)
    await stream_publisher.connect()
    app.state.stream_publisher = stream_publisher
    logger.info("Redis stream publisher connected (Streams)")

    yield

    # ── Shutdown ─────────────────────────────────────────────────
    await stream_publisher.disconnect()
    await event_publisher.disconnect()
    await async_engine.dispose()
    logger.info("Pentra API Gateway shut down")


# ── Application factory ──────────────────────────────────────────────


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""

    app = FastAPI(
        title="Pentra API",
        description="Pentesting-as-a-Service Platform API",
        version="0.1.0",
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        lifespan=lifespan,
    )

    # ── Middleware (order matters: applied bottom-to-top) ─────────
    # 1. CORS — outermost, handles preflight
    configure_cors(app)

    # 2. Request context — request id + lightweight tracing
    app.add_middleware(RequestContextMiddleware)

    # 3. Auth — extracts JWT, populates request.state.user
    app.add_middleware(AuthMiddleware)

    # 4. Rate limit — per-tenant, uses request.state.user.tenant_id
    app.add_middleware(RateLimitMiddleware)

    # ── Exception handlers ───────────────────────────────────────
    app.add_exception_handler(
        RequestValidationError, _validation_error_handler
    )
    app.add_exception_handler(Exception, _generic_error_handler)

    # ── Routers (Phase 3B) ───────────────────────────────────────
    from app.routers import health, auth, tenants, projects, assets, scans

    app.include_router(health.router)
    app.include_router(auth.router, prefix="/auth")
    app.include_router(tenants.router, prefix=f"{settings.api_v1_prefix}/tenants")
    app.include_router(projects.router, prefix=f"{settings.api_v1_prefix}/projects")
    app.include_router(assets.router, prefix=settings.api_v1_prefix)
    app.include_router(scans.router, prefix=f"{settings.api_v1_prefix}/scans")

    return app


# ── Error handlers ───────────────────────────────────────────────────


async def _validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return 422 with readable validation errors."""
    logger.warning("Validation error on %s: %s", request.url.path, exc.errors())
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Validation error",
            "errors": exc.errors(),
            "request_id": getattr(request.state, "request_id", None),
        },
    )


async def _generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all error handler — never leak internals in production."""
    logger.exception("Unhandled error on %s", request.url.path)
    detail = str(exc) if settings.debug else "Internal server error"
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": detail,
            "request_id": getattr(request.state, "request_id", None),
        },
    )


# ── Module-level app instance (used by `uvicorn app.main:app`) ───────
app = create_app()
