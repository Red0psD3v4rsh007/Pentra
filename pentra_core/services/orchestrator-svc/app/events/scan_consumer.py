"""Scan consumer — reads scan.created events from Redis Streams.

Runs as an async background task during the orchestrator's lifespan.
Uses XREADGROUP with the ``orchestrator-cg`` consumer group for
at-least-once delivery with manual XACK.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable, Awaitable

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

STREAM_SCAN_EVENTS = "pentra:stream:scan_events"
CG_ORCHESTRATOR = "orchestrator-cg"
BLOCK_MS = 5000  # 5s block on XREADGROUP
BATCH_SIZE = 10


class ScanConsumer:
    """Consumes scan events from Redis Streams via XREADGROUP.

    Delegates event handling to a callback provided by OrchestratorService.
    """

    def __init__(
        self,
        redis: aioredis.Redis,
        consumer_name: str,
        handler: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        self._redis = redis
        self._consumer = consumer_name
        self._handler = handler
        self._running = False

    async def start(self) -> None:
        """Start consuming in a loop."""
        self._running = True
        await self._ensure_consumer_group()
        logger.info(
            "ScanConsumer started: stream=%s group=%s consumer=%s",
            STREAM_SCAN_EVENTS, CG_ORCHESTRATOR, self._consumer,
        )

        while self._running:
            try:
                messages = await self._redis.xreadgroup(
                    groupname=CG_ORCHESTRATOR,
                    consumername=self._consumer,
                    streams={STREAM_SCAN_EVENTS: ">"},
                    count=BATCH_SIZE,
                    block=BLOCK_MS,
                )

                if not messages:
                    continue

                for stream_name, entries in messages:
                    for msg_id, fields in entries:
                        await self._process_message(msg_id, fields)

            except asyncio.CancelledError:
                logger.info("ScanConsumer stopping (cancelled)")
                break
            except Exception:
                logger.exception("ScanConsumer error — retrying in 2s")
                await asyncio.sleep(2)

    async def stop(self) -> None:
        """Signal the consumer to stop."""
        self._running = False

    async def _process_message(
        self, msg_id: str, fields: dict[str, str]
    ) -> None:
        """Deserialize, handle, and ACK a single message."""
        try:
            raw = fields.get("data", "{}")
            event = json.loads(raw)
            event_type = event.get("event_type", "unknown")

            logger.info("Processing event: %s (msg_id=%s)", event_type, msg_id)

            await self._handler(event)

            # ACK after successful processing
            await self._redis.xack(STREAM_SCAN_EVENTS, CG_ORCHESTRATOR, msg_id)
            logger.debug("ACK: %s", msg_id)

        except Exception:
            logger.exception("Failed to process message %s — will redeliver", msg_id)
            # Don't ACK — message will be redelivered on next XREADGROUP

    async def _ensure_consumer_group(self) -> None:
        """Create the consumer group if it doesn't exist."""
        try:
            await self._redis.xgroup_create(
                STREAM_SCAN_EVENTS, CG_ORCHESTRATOR, id="$", mkstream=True,
            )
        except aioredis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise
