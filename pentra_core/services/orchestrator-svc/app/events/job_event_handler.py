"""Job event handler — processes job.completed and job.failed events.

Reads from ``pentra:stream:job_events`` and delegates to
OrchestratorService for state transitions, retry decisions,
and phase advancement.

Safety mechanisms:
  - ACKs only after successful processing or known duplicate detection
  - Node-level dedup: skips job.completed if node is already completed
  - Logs all processing errors for post-mortem analysis
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from typing import Any, Callable, Awaitable

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

STREAM_JOB_EVENTS = "pentra:stream:job_events"
CG_ORCHESTRATOR = "orchestrator-cg"
BLOCK_MS = 5000
BATCH_SIZE = 20
RECLAIM_BATCH_SIZE = int(os.getenv("ORCHESTRATOR_RECLAIM_BATCH_SIZE", "20"))
RECLAIM_IDLE_MS = int(os.getenv("ORCHESTRATOR_RECLAIM_IDLE_MS", "5000"))


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
                await self._reclaim_idle_messages()

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
        """Process a job event and ACK only after successful handling."""
        should_ack = False
        try:
            raw = fields.get("data", "{}")
            event = json.loads(raw)
            event_type = event.get("event_type", "unknown")

            logger.info("Processing job event: %s (msg_id=%s)", event_type, msg_id)

            if event_type == "job.completed":
                # Node-level dedup: if this node_id is already completed,
                # skip processing to prevent duplicate side-effects
                node_id = event.get("node_id")
                if node_id and await self._is_node_already_completed(node_id):
                    logger.info(
                        "Node %s already completed — skipping duplicate event %s",
                        node_id, msg_id,
                    )
                    should_ack = True
                else:
                    await self._on_completed(event)
                    should_ack = True
            elif event_type == "job.failed":
                await self._on_failed(event)
                should_ack = True
            else:
                logger.warning("Unknown job event type: %s", event_type)
                should_ack = True

        except Exception:
            logger.exception(
                "Failed to process job event %s — leaving unacked for retry/reclaim",
                msg_id,
            )

        if should_ack:
            try:
                await self._redis.xack(STREAM_JOB_EVENTS, CG_ORCHESTRATOR, msg_id)
            except Exception:
                logger.exception("Failed to ACK job event %s", msg_id)

    async def _reclaim_idle_messages(self) -> int:
        """Claim idle pending job events left behind by dead consumers."""
        try:
            result = await self._redis.xautoclaim(
                STREAM_JOB_EVENTS,
                CG_ORCHESTRATOR,
                self._consumer,
                RECLAIM_IDLE_MS,
                "0-0",
                count=RECLAIM_BATCH_SIZE,
            )
        except aioredis.ResponseError as exc:
            if "NOGROUP" in str(exc):
                return 0
            raise

        entries: list[tuple[str, dict[str, str]]] = []
        if isinstance(result, (list, tuple)) and len(result) >= 2:
            raw_entries = result[1] or []
            entries = list(raw_entries)

        if not entries:
            return 0

        logger.info(
            "Reclaimed %d idle job event(s) on %s",
            len(entries),
            STREAM_JOB_EVENTS,
        )
        for msg_id, fields in entries:
            await self._process_message(msg_id, fields)
        return len(entries)

    async def _is_node_already_completed(self, node_id: str) -> bool:
        """Check if a node is already in 'completed' status (dedup guard)."""
        try:
            # Use a lightweight Redis cache to avoid DB round-trips
            cache_key = f"pentra:node_completed:{node_id}"
            cached = await self._redis.get(cache_key)
            if cached == "1":
                return True

            # If not cached, we rely on the orchestrator's own idempotency
            # The orchestrator_service.handle_job_completed checks event_id
            return False
        except Exception:
            return False

    async def _ensure_consumer_group(self) -> None:
        try:
            await self._redis.xgroup_create(
                STREAM_JOB_EVENTS, CG_ORCHESTRATOR, id="$", mkstream=True,
            )
        except aioredis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise
