"""Job event handler — processes job.completed and job.failed events.

Reads from ``pentra:stream:job_events`` and delegates to
OrchestratorService for state transitions, retry decisions,
and phase advancement.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable, Awaitable

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

STREAM_JOB_EVENTS = "pentra:stream:job_events"
CG_ORCHESTRATOR = "orchestrator-cg"
BLOCK_MS = 5000
BATCH_SIZE = 20


class JobEventHandler:
    """Consumes job completion/failure events from Redis Streams."""

    def __init__(
        self,
        redis: aioredis.Redis,
        consumer_name: str,
        on_completed: Callable[[dict[str, Any]], Awaitable[None]],
        on_failed: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        self._redis = redis
        self._consumer = consumer_name
        self._on_completed = on_completed
        self._on_failed = on_failed
        self._running = False

    async def start(self) -> None:
        """Start consuming job events."""
        self._running = True
        await self._ensure_consumer_group()
        logger.info(
            "JobEventHandler started: stream=%s consumer=%s",
            STREAM_JOB_EVENTS, self._consumer,
        )

        while self._running:
            try:
                messages = await self._redis.xreadgroup(
                    groupname=CG_ORCHESTRATOR,
                    consumername=self._consumer,
                    streams={STREAM_JOB_EVENTS: ">"},
                    count=BATCH_SIZE,
                    block=BLOCK_MS,
                )

                if not messages:
                    continue

                for stream_name, entries in messages:
                    for msg_id, fields in entries:
                        await self._process_message(msg_id, fields)

            except asyncio.CancelledError:
                logger.info("JobEventHandler stopping (cancelled)")
                break
            except Exception:
                logger.exception("JobEventHandler error — retrying in 2s")
                await asyncio.sleep(2)

    async def stop(self) -> None:
        self._running = False

    async def _process_message(
        self, msg_id: str, fields: dict[str, str]
    ) -> None:
        try:
            raw = fields.get("data", "{}")
            event = json.loads(raw)
            event_type = event.get("event_type", "unknown")

            logger.info("Processing job event: %s (msg_id=%s)", event_type, msg_id)

            if event_type == "job.completed":
                await self._on_completed(event)
            elif event_type == "job.failed":
                await self._on_failed(event)
            else:
                logger.warning("Unknown job event type: %s", event_type)

            await self._redis.xack(STREAM_JOB_EVENTS, CG_ORCHESTRATOR, msg_id)

        except Exception:
            logger.exception("Failed to process job event %s", msg_id)

    async def _ensure_consumer_group(self) -> None:
        try:
            await self._redis.xgroup_create(
                STREAM_JOB_EVENTS, CG_ORCHESTRATOR, id="$", mkstream=True,
            )
        except aioredis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise
