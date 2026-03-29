"""Orchestrator service — FastAPI application entrypoint.

Starts the Redis Streams consumers as background tasks and
exposes a health endpoint for Kubernetes readiness probes.
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.events.scan_consumer import ScanConsumer
from app.events.job_event_handler import JobEventHandler
from app.services.orchestrator_service import OrchestratorService
from app.engine.scan_watchdog import ScanWatchdog

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://pentra:pentra@localhost:5432/pentra",
)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CONSUMER_NAME = os.getenv(
    "CONSUMER_NAME",
    f"orch-{platform.node()}-{os.getpid()}",
)

# ── Globals ──────────────────────────────────────────────────────────

_engine = create_async_engine(DATABASE_URL, pool_size=20, max_overflow=10)
_session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
    _engine, expire_on_commit=False,
)

_redis: aioredis.Redis | None = None
_consumer_tasks: list[asyncio.Task] = []


# ── Lifespan ─────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start consumers on startup, clean up on shutdown."""
    global _redis

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )

    logger.info("Starting Pentra Orchestrator Service")

    # Connect Redis
    _redis = aioredis.from_url(REDIS_URL, decode_responses=True)

    # Verify DB
    async with _engine.begin() as conn:
        from sqlalchemy import text
        await conn.execute(text("SELECT 1"))
    logger.info("Database connection verified")

    # Create orchestrator service
    orch_svc = OrchestratorService(_session_factory, _redis)

    # Start scan consumer
    scan_consumer = ScanConsumer(
        redis=_redis,
        consumer_name=CONSUMER_NAME,
        handler=orch_svc.handle_scan_event,
    )

    # Start job event handler
    job_handler = JobEventHandler(
        redis=_redis,
        consumer_name=CONSUMER_NAME,
        on_completed=orch_svc.handle_job_completed,
        on_failed=orch_svc.handle_job_failed,
    )

    # Launch as background tasks
    # Start scan watchdog (detects stale scans/nodes)
    watchdog = ScanWatchdog(_session_factory, _redis)

    _consumer_tasks.append(asyncio.create_task(scan_consumer.start()))
    _consumer_tasks.append(asyncio.create_task(job_handler.start()))
    _consumer_tasks.append(asyncio.create_task(watchdog.start()))
    logger.info("Event consumers + watchdog started (consumer=%s)", CONSUMER_NAME)

    yield

    # Shutdown
    logger.info("Shutting down orchestrator...")
    scan_consumer._running = False
    job_handler._running = False
    watchdog.stop()

    for task in _consumer_tasks:
        task.cancel()
    await asyncio.gather(*_consumer_tasks, return_exceptions=True)

    if _redis:
        await _redis.close()
    await _engine.dispose()
    logger.info("Orchestrator shutdown complete")


# ── FastAPI App ──────────────────────────────────────────────────────

app = FastAPI(
    title="Pentra Orchestrator Service",
    description="DAG-based scan orchestration engine",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    """Kubernetes readiness/liveness probe."""
    return {
        "status": "ok",
        "service": "orchestrator-svc",
        "consumer": CONSUMER_NAME,
    }


@app.get("/metrics")
async def metrics():
    """Basic metrics endpoint for monitoring."""
    global _redis
    info: dict = {}
    if _redis:
        try:
            scan_len = await _redis.xlen("pentra:stream:scan_events")
            job_len = await _redis.xlen("pentra:stream:job_events")
            info = {
                "scan_events_pending": scan_len,
                "job_events_pending": job_len,
            }
        except Exception:
            pass
    return {"status": "ok", "streams": info}
