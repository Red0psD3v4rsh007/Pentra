"""Pentra Worker — lightweight async worker loop.

No FastAPI server.  Just a pure async loop that:
  1. Connects to Redis
  2. Creates a JobConsumer for the configured worker family
  3. Processes jobs until killed

Configuration via environment variables:
  WORKER_FAMILY   — recon | network | web | vuln | exploit  (required)
  REDIS_URL       — Redis connection string (default: redis://localhost:6379/0)
  LOG_LEVEL       — DEBUG | INFO | WARNING (default: INFO)
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys

import redis.asyncio as aioredis

from app.engine.container_runner import PREWARM_ENABLED
from app.events.job_consumer import JobConsumer
from app.observability.health_server import WorkerHealthServer
from app.observability.runtime_state import WorkerRuntimeState
from app.services.worker_service import WorkerService

# ── Configuration ────────────────────────────────────────────────────

WORKER_FAMILY = os.getenv("WORKER_FAMILY", "recon")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
WORKER_HEALTH_HOST = os.getenv("WORKER_HEALTH_HOST", "127.0.0.1")
WORKER_HEALTH_PORT = int(os.getenv("WORKER_HEALTH_PORT", "9100"))


def _setup_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        stream=sys.stdout,
    )


async def main() -> None:
    """Worker entrypoint — runs the job consumer loop."""
    _setup_logging()
    logger = logging.getLogger("pentra.worker")

    logger.info("=" * 60)
    logger.info("  Pentra Worker — %s", WORKER_FAMILY)
    logger.info("  Redis: %s", REDIS_URL)
    logger.info("  Health: http://%s:%d/health", WORKER_HEALTH_HOST, WORKER_HEALTH_PORT)
    logger.info("=" * 60)

    # Connect to Redis
    redis = aioredis.from_url(REDIS_URL, decode_responses=True)

    try:
        await redis.ping()
        logger.info("Redis connected")
    except Exception:
        logger.exception("Cannot connect to Redis")
        sys.exit(1)

    # Create worker service and consumer
    runtime_state = WorkerRuntimeState(
        worker_family=WORKER_FAMILY,
        health_host=WORKER_HEALTH_HOST,
        health_port=WORKER_HEALTH_PORT,
        prewarm_enabled=PREWARM_ENABLED,
    )
    service = WorkerService(redis, runtime_state=runtime_state)
    consumer = JobConsumer(redis, family=WORKER_FAMILY, handler=service.execute_job)
    await runtime_state.set_consumer_name(consumer.consumer_name)

    health_server = WorkerHealthServer(
        host=WORKER_HEALTH_HOST,
        port=WORKER_HEALTH_PORT,
        snapshot_provider=runtime_state.snapshot,
    )
    await health_server.start()
    logger.info("Worker health server listening on :%d", health_server.port)

    # Handle shutdown signals
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _shutdown(signame: str) -> None:
        logger.info("Received %s — shutting down", signame)
        shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _shutdown, sig.name)

    prewarm_task = asyncio.create_task(
        _run_startup_prewarm(
            service=service,
            runtime_state=runtime_state,
            logger=logger,
        )
    )

    # Run consumer in background, wait for shutdown
    consumer_task = asyncio.create_task(consumer.start())

    # Wait for shutdown signal
    await shutdown_event.wait()

    # Graceful shutdown
    logger.info("Stopping consumer...")
    await consumer.stop()
    consumer_task.cancel()

    try:
        await consumer_task
    except asyncio.CancelledError:
        pass

    if not prewarm_task.done():
        prewarm_task.cancel()
    try:
        await prewarm_task
    except asyncio.CancelledError:
        pass

    await health_server.stop()

    await redis.close()
    logger.info("Worker shut down cleanly")


async def _run_startup_prewarm(
    *,
    service: WorkerService,
    runtime_state: WorkerRuntimeState,
    logger: logging.Logger,
) -> None:
    """Best-effort startup image prewarm for the configured worker family."""
    images = service.planned_prewarm_images(worker_family=WORKER_FAMILY)
    if not PREWARM_ENABLED:
        await runtime_state.mark_prewarm_skipped(reason="disabled_by_configuration")
        logger.info("Worker image prewarm disabled by configuration")
        return

    if not images:
        await runtime_state.mark_prewarm_skipped(reason="no_family_images_to_prewarm")
        logger.info("No startup images to prewarm for worker family %s", WORKER_FAMILY)
        return

    await runtime_state.mark_prewarm_started(images)

    try:
        results = await service.prewarm_startup_images(worker_family=WORKER_FAMILY)
    except Exception as exc:
        logger.exception("Worker image prewarm failed")
        await runtime_state.mark_prewarm_completed(
            {
                image: {"status": "failed", "detail": str(exc)}
                for image in images
            },
            reason="prewarm_task_error",
        )
        return

    await runtime_state.mark_prewarm_completed(results)


if __name__ == "__main__":
    asyncio.run(main())
