"""Job consumer — XREADGROUP from worker-family Redis stream.

Each worker instance consumes from ``pentra:stream:worker:{family}``
using a consumer group, ensuring at-least-once delivery.

Job payloads are dispatched by the orchestrator's ``job_dispatcher.py``.

Dead-letter mechanism:
  After MAX_REDELIVERIES failed processing attempts, the message is
  moved to a dead-letter queue (``pentra:stream:dlq:{family}``) and
  ACKed from the main stream to prevent infinite looping.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

_WORKER_STREAM_PREFIX = "pentra:stream:worker"
CG_WORKERS = "worker-cg"


def _heartbeat_interval_ms(reclaim_idle_ms: int) -> int:
    raw = int(
        os.getenv(
            "WORKER_RECLAIM_HEARTBEAT_MS",
            str(max(500, reclaim_idle_ms // 3)),
        )
    )
    max_interval = (
        max(250, reclaim_idle_ms - 500)
        if reclaim_idle_ms > 1_000
        else max(250, reclaim_idle_ms // 2)
    )
    return max(250, min(raw, max_interval))


BLOCK_MS = int(os.getenv("WORKER_BLOCK_MS", "1000"))
BATCH_SIZE = 1
RECLAIM_BATCH_SIZE = int(os.getenv("WORKER_RECLAIM_BATCH_SIZE", "10"))
RECLAIM_IDLE_MS = int(os.getenv("WORKER_RECLAIM_IDLE_MS", "5000"))
HEARTBEAT_INTERVAL_MS = _heartbeat_interval_ms(RECLAIM_IDLE_MS)
MAX_REDELIVERIES = int(os.getenv("WORKER_MAX_REDELIVERIES", "3"))
_DLQ_STREAM_PREFIX = "pentra:stream:dlq"
_REDELIVERY_KEY_PREFIX = "pentra:redelivery"
_REDELIVERY_TTL_SECONDS = 3600  # 1 hour
_SCAN_CANCEL_PREFIX = "pentra:scan:cancelled"


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
        self._dlq_stream = f"{_DLQ_STREAM_PREFIX}:{family}"
        self._handler = handler
        self._consumer_name = f"worker-{family}-{os.getpid()}"
        self._running = False

    @property
    def consumer_name(self) -> str:
        return self._consumer_name

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
            "JobConsumer started: stream=%s consumer=%s block_ms=%d reclaim_idle_ms=%d heartbeat_ms=%d",
            self._stream,
            self._consumer_name,
            BLOCK_MS,
            RECLAIM_IDLE_MS,
            HEARTBEAT_INTERVAL_MS,
        )

        while self._running:
            try:
                await self._reclaim_idle_messages()

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

    async def _reclaim_idle_messages(self) -> int:
        """Claim and process idle pending messages for this worker family."""
        try:
            result = await self._redis.xautoclaim(
                self._stream,
                CG_WORKERS,
                self._consumer_name,
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
            "Reclaimed %d idle job message(s) on %s",
            len(entries),
            self._stream,
        )
        for msg_id, fields in entries:
            await self._process_message(msg_id, fields)
        return len(entries)

    async def _refresh_pending_message(self, msg_id: str) -> bool:
        """Refresh this consumer's ownership lease for an in-flight message."""
        try:
            refreshed = await self._redis.xclaim(
                self._stream,
                CG_WORKERS,
                self._consumer_name,
                0,
                [msg_id],
                idle=0,
                justid=True,
            )
        except aioredis.ResponseError as exc:
            if "NOGROUP" in str(exc):
                return False
            raise
        return bool(refreshed)

    async def _heartbeat_pending_message(self, msg_id: str) -> None:
        """Keep a healthy in-flight job from looking abandoned to reclaimers."""
        interval_seconds = HEARTBEAT_INTERVAL_MS / 1000
        while self._running:
            await asyncio.sleep(interval_seconds)
            try:
                refreshed = await self._refresh_pending_message(msg_id)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning(
                    "Failed to heartbeat in-flight job message %s on %s",
                    msg_id,
                    self._stream,
                    exc_info=True,
                )
                continue
            if not refreshed:
                logger.debug(
                    "Stopping heartbeat for message %s on %s; message is no longer pending",
                    msg_id,
                    self._stream,
                )
                return

    async def stop(self) -> None:
        """Signal the consumer to stop."""
        self._running = False

    async def _process_message(
        self, msg_id: str, fields: dict[str, str]
    ) -> None:
        """Process a single job message with dead-letter mechanism.

        On success: ACK the message.
        On failure: increment redelivery counter.
          - If counter < MAX_REDELIVERIES: don't ACK (Redis will redeliver).
          - If counter >= MAX_REDELIVERIES: move to DLQ and ACK.
        """
        raw = fields.get("data", "{}")
        try:
            payload = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            # Unparseable message — dead-letter immediately
            logger.error("Unparseable message %s — dead-lettering", msg_id)
            await self._dead_letter(msg_id, fields, reason="unparseable_payload")
            return

        job_id = payload.get("job_id", "?")
        payload["worker_id"] = self._consumer_name
        payload["claimed_at"] = datetime.now(timezone.utc).isoformat()
        heartbeat_task: asyncio.Task[None] | None = None

        try:
            logger.info(
                "Processing job: id=%s tool=%s scan=%s",
                job_id,
                payload.get("tool", "?"),
                payload.get("scan_id", "?"),
            )

            # Check if scan was cancelled before doing work
            scan_id = payload.get("scan_id", "")
            if scan_id and await self._is_scan_cancelled(scan_id):
                logger.info(
                    "Skipping job %s — scan %s is cancelled",
                    job_id, scan_id,
                )
                await self._redis.xack(self._stream, CG_WORKERS, msg_id)
                await self._clear_redelivery_counter(msg_id)
                return

            heartbeat_task = asyncio.create_task(self._heartbeat_pending_message(msg_id))
            await self._handler(payload)

            # Success — ACK and clear redelivery counter
            await self._redis.xack(self._stream, CG_WORKERS, msg_id)
            await self._clear_redelivery_counter(msg_id)
            logger.debug("ACK %s:%s", self._stream, msg_id)

        except Exception as exc:
            logger.exception("Failed to process job %s (msg %s)", job_id, msg_id)

            # Increment redelivery counter
            count = await self._increment_redelivery_counter(msg_id)

            if count >= MAX_REDELIVERIES:
                logger.error(
                    "Job %s exceeded max redeliveries (%d) — dead-lettering",
                    job_id, MAX_REDELIVERIES,
                )
                # Emit job.failed before dead-lettering so orchestrator
                # can propagate the failure through the DAG
                await self._emit_failure_for_dead_letter(payload, str(exc))
                await self._dead_letter(
                    msg_id, fields,
                    reason=f"max_redeliveries_exceeded: {exc}",
                )
            else:
                # ACK this delivery to prevent Redis infinite re-read of
                # the same message in the > cursor. The redelivery counter
                # above tracks attempts. We re-enqueue explicitly if needed.
                logger.warning(
                    "Job %s attempt %d/%d failed — will retry via XPENDING claim",
                    job_id, count, MAX_REDELIVERIES,
                )
                # Don't ACK — let Redis XPENDING mechanism redeliver
                # after the idle timeout (XAUTOCLAIM can pick it up)
        finally:
            if heartbeat_task is not None:
                heartbeat_task.cancel()
                with suppress(asyncio.CancelledError):
                    await heartbeat_task

    async def _dead_letter(
        self, msg_id: str, fields: dict[str, str], *, reason: str
    ) -> None:
        """Move a message to the dead-letter queue and ACK the original."""
        try:
            dlq_payload = {
                "original_stream": self._stream,
                "original_msg_id": msg_id,
                "reason": reason,
                "data": fields.get("data", "{}"),
            }
            await self._redis.xadd(
                self._dlq_stream,
                {"data": json.dumps(dlq_payload)},
                maxlen=10_000,
                approximate=True,
            )
        except Exception:
            logger.exception("Failed to write to DLQ for msg %s", msg_id)

        # Always ACK the original to stop redelivery
        try:
            await self._redis.xack(self._stream, CG_WORKERS, msg_id)
        except Exception:
            logger.exception("Failed to ACK dead-lettered msg %s", msg_id)

        await self._clear_redelivery_counter(msg_id)

    async def _emit_failure_for_dead_letter(
        self, payload: dict[str, Any], error_message: str
    ) -> None:
        """Emit a job.failed event so the orchestrator can propagate DAG failure."""
        try:
            from app.events.event_emitter import EventEmitter
            emitter = EventEmitter(self._redis)
            await emitter.emit_job_failed(
                job_id=uuid.UUID(payload["job_id"]),
                scan_id=uuid.UUID(payload["scan_id"]),
                tenant_id=uuid.UUID(payload["tenant_id"]),
                node_id=uuid.UUID(payload["node_id"]),
                dag_id=uuid.UUID(payload["dag_id"]),
                tool=payload.get("tool", "unknown"),
                error_code="DEAD_LETTERED",
                error_message=f"Job dead-lettered after {MAX_REDELIVERIES} attempts: {error_message[:500]}",
                target=payload.get("target", ""),
            )
        except Exception:
            logger.exception("Failed to emit failure event for dead-lettered job")

    async def _increment_redelivery_counter(self, msg_id: str) -> int:
        """Increment and return the redelivery counter for a message."""
        key = f"{_REDELIVERY_KEY_PREFIX}:{msg_id}"
        count = await self._redis.incr(key)
        await self._redis.expire(key, _REDELIVERY_TTL_SECONDS)
        return int(count)

    async def _clear_redelivery_counter(self, msg_id: str) -> None:
        """Clear the redelivery counter after successful processing or DLQ."""
        key = f"{_REDELIVERY_KEY_PREFIX}:{msg_id}"
        try:
            await self._redis.delete(key)
        except Exception:
            pass

    async def _is_scan_cancelled(self, scan_id: str) -> bool:
        """Check if a scan has been cancelled via Redis flag."""
        try:
            result = await self._redis.get(f"{_SCAN_CANCEL_PREFIX}:{scan_id}")
            return result is not None
        except Exception:
            return False
