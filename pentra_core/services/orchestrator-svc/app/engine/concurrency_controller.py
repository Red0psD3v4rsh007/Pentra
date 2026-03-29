"""Concurrency controller — distributed locking and idempotency.

Provides:
  - Redis-based distributed locks for scan-level operations
  - Idempotent event processing via processed-event tracking
  - Per-tenant concurrency enforcement
"""

from __future__ import annotations

__classification__ = "runtime_hot_path"

import logging
import uuid

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

# Lock key prefixes
_LOCK_PREFIX = "pentra:lock:scan"
_PROCESSED_PREFIX = "pentra:processed"
_TENANT_ACTIVE_PREFIX = "pentra:tenant:active_scans"
_LOCK_TTL_SECONDS = 120
_PROCESSED_TTL_SECONDS = 86400  # 24 hours
MAX_TENANT_CONCURRENT_SCANS = 5  # configurable per deployment


class ConcurrencyController:
    """Distributed locking and idempotency via Redis."""

    def __init__(self, redis: aioredis.Redis) -> None:
        self._redis = redis

    # ── Distributed Locks ────────────────────────────────────────

    async def acquire_scan_lock(
        self, scan_id: uuid.UUID, holder: str = "orchestrator"
    ) -> bool:
        """Acquire an exclusive lock on a scan.

        Uses SET NX EX for atomic lock acquisition with TTL.
        Returns True if lock acquired, False if already held.
        """
        key = f"{_LOCK_PREFIX}:{scan_id}"
        acquired = await self._redis.set(
            key, holder, nx=True, ex=_LOCK_TTL_SECONDS
        )
        if acquired:
            logger.debug("Lock acquired: %s (holder=%s)", key, holder)
        return bool(acquired)

    async def release_scan_lock(
        self, scan_id: uuid.UUID, holder: str = "orchestrator"
    ) -> bool:
        """Release the lock on a scan (only if we hold it)."""
        key = f"{_LOCK_PREFIX}:{scan_id}"
        # Lua script for atomic check-and-delete
        script = """
        if redis.call("GET", KEYS[1]) == ARGV[1] then
            return redis.call("DEL", KEYS[1])
        else
            return 0
        end
        """
        result = await self._redis.eval(script, 1, key, holder)
        released = int(result) == 1
        if released:
            logger.debug("Lock released: %s", key)
        return released

    async def extend_scan_lock(
        self, scan_id: uuid.UUID, holder: str = "orchestrator"
    ) -> bool:
        """Extend the TTL on a held lock (heartbeat)."""
        key = f"{_LOCK_PREFIX}:{scan_id}"
        script = """
        if redis.call("GET", KEYS[1]) == ARGV[1] then
            return redis.call("EXPIRE", KEYS[1], ARGV[2])
        else
            return 0
        end
        """
        result = await self._redis.eval(
            script, 1, key, holder, str(_LOCK_TTL_SECONDS)
        )
        return int(result) == 1

    # ── Idempotent Event Processing ──────────────────────────────

    async def is_event_processed(self, event_id: str) -> bool:
        """Check if an event has already been processed (dedup)."""
        key = f"{_PROCESSED_PREFIX}:{event_id}"
        return bool(await self._redis.exists(key))

    async def mark_event_processed(self, event_id: str) -> None:
        """Mark an event as processed with a TTL for cleanup."""
        key = f"{_PROCESSED_PREFIX}:{event_id}"
        await self._redis.set(key, "1", ex=_PROCESSED_TTL_SECONDS)

    # ── Tenant Concurrency ───────────────────────────────────────

    async def increment_tenant_scans(self, tenant_id: uuid.UUID) -> int:
        """Increment active scan count for a tenant. Returns new count."""
        key = f"{_TENANT_ACTIVE_PREFIX}:{tenant_id}"
        count = await self._redis.incr(key)
        await self._redis.expire(key, 86400)
        return int(count)

    async def decrement_tenant_scans(self, tenant_id: uuid.UUID) -> int:
        """Decrement active scan count for a tenant. Returns new count."""
        key = f"{_TENANT_ACTIVE_PREFIX}:{tenant_id}"
        count = await self._redis.decr(key)
        if count <= 0:
            await self._redis.delete(key)
            return 0
        return int(count)

    async def can_start_scan(
        self, tenant_id: uuid.UUID, *, max_concurrent: int | None = None
    ) -> tuple[bool, str]:
        """Check if a tenant can start a new scan.

        Returns (allowed, reason).  When *allowed* is ``False`` the caller
        should surface *reason* to the user as a clear error message.
        """
        limit = max_concurrent or MAX_TENANT_CONCURRENT_SCANS
        key = f"{_TENANT_ACTIVE_PREFIX}:{tenant_id}"
        current = int(await self._redis.get(key) or 0)
        if current >= limit:
            return False, (
                f"Concurrency limit reached ({current}/{limit} active scans). "
                "Wait for a running scan to complete or cancel one before starting a new scan."
            )
        return True, ""
