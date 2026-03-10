"""Job consumer — XREADGROUP from worker-family Redis stream.

Each worker instance consumes from ``pentra:stream:worker:{family}``
using a consumer group, ensuring at-least-once delivery.

Job payloads are dispatched by the orchestrator's ``job_dispatcher.py``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from typing import Any, Callable, Coroutine

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

_WORKER_STREAM_PREFIX = "pentra:stream:worker"
CG_WORKERS = "worker-cg"
BLOCK_MS = 5_000  # 5s block on XREADGROUP
BATCH_SIZE = 1


class JobConsumer:
    """Consumes jobs from a worker-family Redis stream.

    Usage::

        consumer = JobConsumer(redis, family="recon", handler=svc.execute_job)
        await consumer.start()  # blocks forever, processing jobs
    """

    def __init__(
        self,
        redis: aioredis.Redis,
        family: str,
        handler: Callable[[dict[str, Any]], Coroutine],
    ) -> None:
        self._redis = redis
        self._family = family
        self._stream = f"{_WORKER_STREAM_PREFIX}:{family}"
        self._handler = handler
        self._consumer_name = f"worker-{family}-{os.getpid()}"
        self._running = False

    async def start(self) -> None:
        """Start consuming jobs. Blocks until stop() is called."""
        # Ensure consumer group exists
        try:
            await self._redis.xgroup_create(
                self._stream, CG_WORKERS, id="0", mkstream=True,
            )
            logger.info("Created consumer group %s on %s", CG_WORKERS, self._stream)
        except aioredis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

        self._running = True
        logger.info(
            "JobConsumer started: stream=%s consumer=%s",
            self._stream, self._consumer_name,
        )

        while self._running:
            try:
                messages = await self._redis.xreadgroup(
                    CG_WORKERS,
                    self._consumer_name,
                    {self._stream: ">"},
                    count=BATCH_SIZE,
                    block=BLOCK_MS,
                )

                if not messages:
                    continue

                for stream_name, entries in messages:
                    for msg_id, fields in entries:
                        await self._process_message(msg_id, fields)

            except asyncio.CancelledError:
                logger.info("JobConsumer cancelled")
                break
            except Exception:
                logger.exception("Error in job consumer loop")
                await asyncio.sleep(1)

        logger.info("JobConsumer stopped")

    async def stop(self) -> None:
        """Signal the consumer to stop."""
        self._running = False

    async def _process_message(
        self, msg_id: str, fields: dict[str, str]
    ) -> None:
        """Process a single job message."""
        try:
            raw = fields.get("data", "{}")
            payload = json.loads(raw) if isinstance(raw, str) else raw

            logger.info(
                "Processing job: id=%s tool=%s scan=%s",
                payload.get("job_id", "?"),
                payload.get("tool", "?"),
                payload.get("scan_id", "?"),
            )

            await self._handler(payload)

            # Acknowledge after successful processing
            await self._redis.xack(self._stream, CG_WORKERS, msg_id)
            logger.debug("ACK %s:%s", self._stream, msg_id)

        except Exception:
            logger.exception("Failed to process message %s", msg_id)
            # Don't ACK — message will be redelivered via XPENDING
