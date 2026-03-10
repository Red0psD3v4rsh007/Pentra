"""Event emitter — publishes job.completed / job.failed to Redis Streams.

Maintains the exact event contract expected by
``orchestrator-svc/app/events/job_event_handler.py``.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

STREAM_JOB_EVENTS = "pentra:stream:job_events"
_MAX_STREAM_LEN = 100_000


class EventEmitter:
    """Publishes worker events to the orchestrator's job_events stream."""

    def __init__(self, redis: aioredis.Redis) -> None:
        self._redis = redis

    async def emit_job_completed(
        self,
        *,
        job_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        node_id: uuid.UUID,
        dag_id: uuid.UUID,
        tool: str,
        output_ref: str,
        output_summary: dict | None = None,
        target: str = "",
        priority: str = "normal",
    ) -> str:
        """Publish a job.completed event."""
        payload = {
            "event_type": "job.completed",
            "event_id": str(uuid.uuid4()),
            "job_id": str(job_id),
            "scan_id": str(scan_id),
            "tenant_id": str(tenant_id),
            "node_id": str(node_id),
            "dag_id": str(dag_id),
            "tool": tool,
            "output_ref": output_ref,
            "output_summary": output_summary or {},
            "target": target,
            "priority": priority,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        msg_id = await self._redis.xadd(
            STREAM_JOB_EVENTS,
            {"data": json.dumps(payload, default=str)},
            maxlen=_MAX_STREAM_LEN,
            approximate=True,
        )
        logger.info("Emitted job.completed: job=%s tool=%s msg=%s", job_id, tool, msg_id)
        return msg_id

    async def emit_job_failed(
        self,
        *,
        job_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        node_id: uuid.UUID,
        dag_id: uuid.UUID,
        tool: str,
        error_code: str,
        error_message: str,
        target: str = "",
        priority: str = "normal",
    ) -> str:
        """Publish a job.failed event."""
        payload = {
            "event_type": "job.failed",
            "event_id": str(uuid.uuid4()),
            "job_id": str(job_id),
            "scan_id": str(scan_id),
            "tenant_id": str(tenant_id),
            "node_id": str(node_id),
            "dag_id": str(dag_id),
            "tool": tool,
            "error_code": error_code,
            "error_message": error_message,
            "target": target,
            "priority": priority,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        msg_id = await self._redis.xadd(
            STREAM_JOB_EVENTS,
            {"data": json.dumps(payload, default=str)},
            maxlen=_MAX_STREAM_LEN,
            approximate=True,
        )
        logger.warning("Emitted job.failed: job=%s tool=%s err=%s", job_id, tool, error_code)
        return msg_id
