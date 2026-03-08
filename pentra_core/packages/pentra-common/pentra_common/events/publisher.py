"""Redis-based event publisher for inter-service communication.

All Pentra services (api-gateway, orchestrator, workers, AI) use this
module to publish domain events via Redis Pub/Sub.  The event schema
is standardised so any subscriber can deserialise the payload.

Usage::

    publisher = EventPublisher(redis_url="redis://localhost:6379/0")
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
        job_count=len(jobs),
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

# ── Channel names ────────────────────────────────────────────────────
CHANNEL_SCAN_CREATED = "pentra:events:scan:created"
CHANNEL_SCAN_STATUS = "pentra:events:scan:status"
CHANNEL_SCAN_COMPLETED = "pentra:events:scan:completed"
CHANNEL_AUDIT = "pentra:events:audit"


class EventPublisher:
    """Async Redis Pub/Sub event publisher — reusable by all services."""

    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._redis: aioredis.Redis | None = None

    async def connect(self) -> None:
        """Open the Redis connection pool."""
        self._redis = aioredis.from_url(
            self._redis_url,
            decode_responses=True,
        )
        logger.info("EventPublisher connected to Redis")

    async def disconnect(self) -> None:
        """Close the Redis connection pool."""
        if self._redis:
            await self._redis.close()
            logger.info("EventPublisher disconnected from Redis")

    # ── Generic publish ──────────────────────────────────────────

    async def publish(self, channel: str, payload: dict[str, Any]) -> None:
        """Publish a JSON payload to a Redis channel."""
        if not self._redis:
            raise RuntimeError("EventPublisher not connected — call connect() first")

        message = json.dumps(payload, default=str)
        await self._redis.publish(channel, message)
        logger.debug("Published to %s: %s", channel, message[:200])

    # ── Domain-specific publishers ───────────────────────────────

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
        job_count: int = 0,
    ) -> None:
        """Publish ``scan.created`` — consumed by MOD-04 orchestrator."""
        await self.publish(
            CHANNEL_SCAN_CREATED,
            {
                "event_type": "scan.created",
                "scan_id": str(scan_id),
                "tenant_id": str(tenant_id),
                "asset_id": str(asset_id),
                "project_id": str(project_id),
                "scan_type": scan_type,
                "priority": priority,
                "target": target,
                "asset_type": asset_type,
                "config": config or {},
                "job_count": job_count,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    async def publish_scan_status_changed(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        old_status: str,
        new_status: str,
        progress: int | None = None,
    ) -> None:
        """Publish ``scan.status_changed`` — for dashboards and audit."""
        await self.publish(
            CHANNEL_SCAN_STATUS,
            {
                "event_type": "scan.status_changed",
                "scan_id": str(scan_id),
                "tenant_id": str(tenant_id),
                "old_status": old_status,
                "new_status": new_status,
                "progress": progress,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    async def publish_audit_event(
        self,
        *,
        tenant_id: uuid.UUID,
        user_id: uuid.UUID,
        action: str,
        resource_type: str,
        resource_id: str,
        details: dict | None = None,
    ) -> None:
        """Publish an audit event for security logging."""
        await self.publish(
            CHANNEL_AUDIT,
            {
                "event_type": "audit",
                "tenant_id": str(tenant_id),
                "user_id": str(user_id),
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "details": details or {},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
