"""Redis Streams publisher for durable inter-service events.

Replaces Redis Pub/Sub for events that require acknowledgement and
replay guarantees (scan.created, scan.cancelled, job.completed, job.failed,
scan.completed).

Events are published via ``XADD`` to named streams with automatic
trimming (``MAXLEN ~``).  Consumer groups on the receiving side use
``XREADGROUP`` + ``XACK`` for at-least-once delivery.

Usage::

    publisher = StreamPublisher(redis_url="redis://localhost:6379/0")
    await publisher.connect()

    await publisher.publish_scan_created(
        scan_id=scan.id,
        tenant_id=scan.tenant_id,
        asset_id=scan.asset_id,
        project_id=asset.project_id,
        scan_type=scan.scan_type,
        priority=scan.priority,
        target=asset.target,
        asset_type=asset.asset_type,
        config=scan.config,
        created_by=user.user_id,
    )

    await publisher.disconnect()
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

# ── Stream names ─────────────────────────────────────────────────────

STREAM_SCAN_EVENTS = "pentra:stream:scan_events"
STREAM_JOB_EVENTS = "pentra:stream:job_events"
STREAM_SCAN_STATUS = "pentra:stream:scan_status"
STREAM_DLQ = "pentra:stream:dlq"

# ── Consumer group names ─────────────────────────────────────────────

CG_ORCHESTRATOR = "orchestrator-cg"
CG_DASHBOARD = "dashboard-cg"
CG_API = "api-cg"

# Approximate max stream length (~24h at high throughput)
_MAX_STREAM_LEN = 100_000


class StreamPublisher:
    """Durable Redis Streams event publisher.

    All events are published via ``XADD`` with approximate trimming.
    Each event includes a unique ``event_id`` for idempotency.
    """

    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._redis: aioredis.Redis | None = None

    async def connect(self) -> None:
        """Open the Redis connection pool."""
        self._redis = aioredis.from_url(
            self._redis_url,
            decode_responses=True,
        )
        # Ensure consumer groups exist (idempotent)
        await self._ensure_consumer_groups()
        logger.info("StreamPublisher connected to Redis")

    async def disconnect(self) -> None:
        """Close the Redis connection pool."""
        if self._redis:
            await self._redis.close()
            logger.info("StreamPublisher disconnected from Redis")

    # ── Consumer group setup ─────────────────────────────────────

    async def _ensure_consumer_groups(self) -> None:
        """Create consumer groups if they don't already exist."""
        groups = [
            (STREAM_SCAN_EVENTS, CG_ORCHESTRATOR),
            (STREAM_JOB_EVENTS, CG_ORCHESTRATOR),
            (STREAM_SCAN_STATUS, CG_DASHBOARD),
            (STREAM_SCAN_STATUS, CG_API),
        ]
        for stream, group in groups:
            try:
                await self._redis.xgroup_create(
                    stream, group, id="$", mkstream=True
                )
                logger.debug("Created consumer group %s on %s", group, stream)
            except aioredis.ResponseError as exc:
                # Group already exists — this is expected on restart
                if "BUSYGROUP" in str(exc):
                    pass
                else:
                    raise

    # ── Generic publish ──────────────────────────────────────────

    async def xadd(
        self, stream: str, fields: dict[str, str], maxlen: int = _MAX_STREAM_LEN
    ) -> str:
        """Publish a message to a Redis Stream.

        Returns the message ID assigned by Redis.
        """
        if not self._redis:
            raise RuntimeError("StreamPublisher not connected — call connect() first")

        message_id = await self._redis.xadd(
            stream, fields, maxlen=maxlen, approximate=True
        )
        logger.debug("XADD %s: id=%s", stream, message_id)
        return message_id

    def _serialize(self, payload: dict[str, Any]) -> dict[str, str]:
        """Serialize a payload dict to Redis Stream field format.

        Redis Streams require string values, so we JSON-encode complex
        fields and stringify simple ones.
        """
        return {"data": json.dumps(payload, default=str)}

    # ── scan.created ─────────────────────────────────────────────

    async def publish_scan_created(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        asset_id: uuid.UUID,
        project_id: uuid.UUID,
        scan_type: str,
        priority: str,
        target: str,
        asset_type: str,
        config: dict | None = None,
        created_by: uuid.UUID | None = None,
    ) -> str:
        """Publish ``scan.created`` event — consumed by orchestrator.

        Returns the Redis Stream message ID.
        """
        payload = {
            "event_type": "scan.created",
            "event_id": str(uuid.uuid4()),
            "scan_id": str(scan_id),
            "tenant_id": str(tenant_id),
            "asset_id": str(asset_id),
            "project_id": str(project_id),
            "scan_type": scan_type,
            "priority": priority,
            "target": target,
            "asset_type": asset_type,
            "config": config or {},
            "created_by": str(created_by) if created_by else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return await self.xadd(STREAM_SCAN_EVENTS, self._serialize(payload))

    # ── scan.cancelled ───────────────────────────────────────────

    async def publish_scan_cancelled(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        old_status: str,
        new_status: str = "cancelled",
        cancelled_by: uuid.UUID | None = None,
    ) -> str:
        """Publish ``scan.cancelled`` event — consumed by orchestrator."""
        payload = {
            "event_type": "scan.cancelled",
            "event_id": str(uuid.uuid4()),
            "scan_id": str(scan_id),
            "tenant_id": str(tenant_id),
            "old_status": old_status,
            "new_status": new_status,
            "cancelled_by": str(cancelled_by) if cancelled_by else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return await self.xadd(STREAM_SCAN_EVENTS, self._serialize(payload))

    async def publish_scan_resumed(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        old_status: str,
        new_status: str = "running",
        resume_mode: str = "continue",
        resumed_by: uuid.UUID | None = None,
    ) -> str:
        """Publish ``scan.resumed`` event — consumed by the orchestrator."""
        payload = {
            "event_type": "scan.resumed",
            "event_id": str(uuid.uuid4()),
            "scan_id": str(scan_id),
            "tenant_id": str(tenant_id),
            "old_status": old_status,
            "new_status": new_status,
            "resume_mode": resume_mode,
            "resumed_by": str(resumed_by) if resumed_by else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return await self.xadd(STREAM_SCAN_EVENTS, self._serialize(payload))

    # ── job.completed ────────────────────────────────────────────

    async def publish_job_completed(
        self,
        *,
        job_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        node_id: uuid.UUID | None = None,
        phase: int,
        tool: str,
        worker_id: str,
        output_ref: str,
        output_summary: dict | None = None,
        findings_count: int = 0,
        duration_seconds: int = 0,
    ) -> str:
        """Publish ``job.completed`` event — consumed by orchestrator."""
        payload = {
            "event_type": "job.completed",
            "event_id": str(uuid.uuid4()),
            "job_id": str(job_id),
            "scan_id": str(scan_id),
            "tenant_id": str(tenant_id),
            "node_id": str(node_id) if node_id else None,
            "phase": phase,
            "tool": tool,
            "worker_id": worker_id,
            "output_ref": output_ref,
            "output_summary": output_summary or {},
            "findings_count": findings_count,
            "duration_seconds": duration_seconds,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return await self.xadd(STREAM_JOB_EVENTS, self._serialize(payload))

    # ── job.failed ───────────────────────────────────────────────

    async def publish_job_failed(
        self,
        *,
        job_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        node_id: uuid.UUID | None = None,
        phase: int,
        tool: str,
        worker_id: str,
        error_code: str,
        error_message: str,
        retry_count: int = 0,
        max_retries: int = 0,
        checkpoint_ref: str | None = None,
        duration_seconds: int = 0,
    ) -> str:
        """Publish ``job.failed`` event — consumed by orchestrator."""
        payload = {
            "event_type": "job.failed",
            "event_id": str(uuid.uuid4()),
            "job_id": str(job_id),
            "scan_id": str(scan_id),
            "tenant_id": str(tenant_id),
            "node_id": str(node_id) if node_id else None,
            "phase": phase,
            "tool": tool,
            "worker_id": worker_id,
            "error_code": error_code,
            "error_message": error_message,
            "retry_count": retry_count,
            "max_retries": max_retries,
            "checkpoint_ref": checkpoint_ref,
            "duration_seconds": duration_seconds,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return await self.xadd(STREAM_JOB_EVENTS, self._serialize(payload))

    # ── scan.completed ───────────────────────────────────────────

    async def publish_scan_completed(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        status: str,
        progress: int = 100,
        total_findings: int = 0,
        severity_breakdown: dict | None = None,
        total_phases: int = 0,
        phases_completed: int = 0,
        phases_partial: int = 0,
        phases_failed: int = 0,
        duration_seconds: int = 0,
        report_ref: str | None = None,
    ) -> str:
        """Publish ``scan.completed`` event — consumed by dashboards."""
        payload = {
            "event_type": "scan.completed",
            "event_id": str(uuid.uuid4()),
            "scan_id": str(scan_id),
            "tenant_id": str(tenant_id),
            "status": status,
            "progress": progress,
            "total_findings": total_findings,
            "severity_breakdown": severity_breakdown or {},
            "total_phases": total_phases,
            "phases_completed": phases_completed,
            "phases_partial": phases_partial,
            "phases_failed": phases_failed,
            "duration_seconds": duration_seconds,
            "report_ref": report_ref,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return await self.xadd(STREAM_SCAN_STATUS, self._serialize(payload))

    # ── scan.status_changed ──────────────────────────────────────

    async def publish_scan_status_changed(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        old_status: str,
        new_status: str,
        progress: int | None = None,
    ) -> str:
        """Publish ``scan.status_changed`` — for dashboards and API."""
        payload = {
            "event_type": "scan.status_changed",
            "event_id": str(uuid.uuid4()),
            "scan_id": str(scan_id),
            "tenant_id": str(tenant_id),
            "old_status": old_status,
            "new_status": new_status,
            "progress": progress,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return await self.xadd(STREAM_SCAN_STATUS, self._serialize(payload))
