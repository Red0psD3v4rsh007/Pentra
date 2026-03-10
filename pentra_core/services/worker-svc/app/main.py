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

from app.events.job_consumer import JobConsumer
from app.services.worker_service import WorkerService

# ── Configuration ────────────────────────────────────────────────────

WORKER_FAMILY = os.getenv("WORKER_FAMILY", "recon")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()


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
    service = WorkerService(redis)
    consumer = JobConsumer(redis, family=WORKER_FAMILY, handler=service.execute_job)

    # Handle shutdown signals
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _shutdown(signame: str) -> None:
        logger.info("Received %s — shutting down", signame)
        shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _shutdown, sig.name)

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

    await redis.close()
    logger.info("Worker shut down cleanly")


if __name__ == "__main__":
    asyncio.run(main())
