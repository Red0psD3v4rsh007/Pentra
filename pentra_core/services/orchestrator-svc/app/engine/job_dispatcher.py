"""Job dispatcher — creates ScanJob rows and publishes to worker streams.

Routes jobs to the correct worker-family stream:
  pentra:stream:worker:recon
  pentra:stream:worker:network
  pentra:stream:worker:web
  pentra:stream:worker:vuln
  pentra:stream:worker:exploit
"""

from __future__ import annotations

__classification__ = "runtime_hot_path"

import json
import logging
import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.engine.dependency_resolver import ReadyNode

logger = logging.getLogger(__name__)

# Worker stream prefix
_WORKER_STREAM_PREFIX = "pentra:stream:worker"
_MAX_STREAM_LEN = 100_000
_RELAY_LOCK_KEY = "pentra:lock:job_dispatch_relay"
_RELAY_LOCK_TTL_SECONDS = 30
_DUPLICATE_STREAM_ID_MARKER = "equal or smaller than the target stream top item"


class JobDispatcher:
    """Dispatches ready DAG nodes as ScanJobs to worker-family Redis streams."""

    def __init__(
        self,
        session: AsyncSession,
        redis: aioredis.Redis,
    ) -> None:
        self._session = session
        self._redis = redis

    async def dispatch_nodes(
        self,
        nodes: list[ReadyNode],
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        target: str,
        priority: str = "normal",
        config: dict | None = None,
    ) -> list[uuid.UUID]:
        """Stage a batch of ready nodes for durable post-commit dispatch.

        For each node:
          1. Create a ScanJob row in PostgreSQL
          2. Mark the node as 'scheduled'
          3. Write the worker-stream payload into the DB outbox

        Returns a list of created job IDs.
        """
        job_ids: list[uuid.UUID] = []
        now = datetime.now(timezone.utc).isoformat()

        for node in nodes:
            job_id = uuid.uuid4()
            job_config = _merge_configs(config or {}, node.config or {})
            retry_count_result = await self._session.execute(text("""
                SELECT COALESCE(j.retry_count, 0) AS retry_count
                FROM scan_nodes n
                LEFT JOIN scan_jobs j ON j.id = n.job_id
                WHERE n.id = :nid
            """), {"nid": str(node.node_id)})
            retry_count_row = retry_count_result.mappings().first()
            inherited_retry_count = int(retry_count_row["retry_count"]) if retry_count_row else 0

            # 1 — Create ScanJob (include all NOT NULL columns)
            await self._session.execute(text("""
                INSERT INTO scan_jobs
                    (id, scan_id, tenant_id, phase, tool, status,
                     priority, retry_count, max_retries, timeout_seconds)
                VALUES
                    (:id, :sid, :tid, :phase, :tool, 'queued',
                     :priority, :retry_count, :max_retries, :timeout)
            """), {
                "id": str(job_id), "sid": str(scan_id), "tid": str(tenant_id),
                "phase": await self._get_phase_number(node.phase_id),
                "tool": node.tool,
                "priority": priority,
                "retry_count": inherited_retry_count,
                "max_retries": node.config.get("max_retries", 2),
                "timeout": node.config.get("timeout_seconds", 600),
            })

            # 2 — Mark node as scheduled (ready → scheduled)
            await self._session.execute(text("""
                UPDATE scan_nodes SET status = 'scheduled'
                WHERE id = :id AND status = 'ready'
            """), {"id": str(node.node_id)})

            # Link job to node (store job_id in the node for cross-reference)
            await self._session.execute(text("""
                UPDATE scan_nodes SET job_id = :jid WHERE id = :nid
            """), {"jid": str(job_id), "nid": str(node.node_id)})

            stream = f"{_WORKER_STREAM_PREFIX}:{node.worker_family}"
            payload = {
                "job_id": str(job_id),
                "scan_id": str(scan_id),
                "tenant_id": str(tenant_id),
                "node_id": str(node.node_id),
                "dag_id": str(node.dag_id),
                "tool": node.tool,
                "worker_family": node.worker_family,
                "target": target,
                "config": json.dumps(job_config),
                "input_refs": json.dumps(node.input_refs),
                "dispatched_at": now,
            }
            await self._session.execute(
                text("""
                    INSERT INTO job_dispatch_outbox
                        (job_id, scan_id, tenant_id, node_id, worker_stream, payload)
                    VALUES
                        (:job_id, :scan_id, :tenant_id, :node_id, :worker_stream, CAST(:payload AS jsonb))
                    ON CONFLICT (job_id) DO NOTHING
                """),
                {
                    "job_id": str(job_id),
                    "scan_id": str(scan_id),
                    "tenant_id": str(tenant_id),
                    "node_id": str(node.node_id),
                    "worker_stream": stream,
                    "payload": json.dumps(payload),
                },
            )

            job_ids.append(job_id)

            logger.info(
                "Staged job %s for dispatch: tool=%s → stream=%s (scan=%s node=%s)",
                job_id, node.tool, stream, scan_id, node.node_id,
            )

        await self._session.flush()
        return job_ids

    async def publish_pending_jobs(self, *, limit: int = 100) -> int:
        """Publish committed outbox entries to Redis Streams in durable order."""
        return await self.publish_pending_jobs_for_tenant(limit=limit, tenant_id=None)

    async def publish_pending_jobs_for_tenant(
        self,
        *,
        limit: int = 100,
        tenant_id: uuid.UUID | None,
    ) -> int:
        """Publish committed outbox entries, optionally scoped to one tenant."""
        if limit <= 0:
            return 0

        holder = f"relay-{uuid.uuid4()}"
        if not await self._acquire_relay_lock(holder):
            return 0

        published = 0
        try:
            rows = await self._load_pending_outbox_rows(limit=limit, tenant_id=tenant_id)
            for row in rows:
                scheduled_at = datetime.now(timezone.utc)
                scheduled_at_iso = scheduled_at.isoformat()
                message_id = self._stream_message_id(row["created_at"], int(row["id"]))
                payload = dict(row["payload"])
                payload["scheduled_at"] = scheduled_at_iso
                payload_json = json.dumps(payload, default=str)

                try:
                    await self._redis.xadd(
                        row["worker_stream"],
                        {"data": payload_json},
                        id=message_id,
                        maxlen=_MAX_STREAM_LEN,
                        approximate=True,
                    )
                except aioredis.ResponseError as exc:
                    if _DUPLICATE_STREAM_ID_MARKER not in str(exc):
                        await self._mark_outbox_error(int(row["id"]), str(exc))
                        raise

                await self._session.execute(
                    text("""
                        UPDATE job_dispatch_outbox
                        SET status = 'published',
                            stream_message_id = :message_id,
                            published_at = NOW(),
                            last_error = NULL
                        WHERE id = :id
                    """),
                    {
                        "id": int(row["id"]),
                        "message_id": message_id,
                    },
                )
                await self._session.execute(
                    text("""
                        UPDATE scan_jobs
                        SET status = 'scheduled'
                            , scheduled_at = COALESCE(scheduled_at, :scheduled_at)
                        WHERE id = :job_id AND status = 'queued'
                    """),
                    {
                        "job_id": str(row["job_id"]),
                        "scheduled_at": scheduled_at,
                    },
                )
                published += 1
            await self._session.flush()
            return published
        finally:
            await self._release_relay_lock(holder)

    async def _load_pending_outbox_rows(
        self,
        *,
        limit: int,
        tenant_id: uuid.UUID | None,
    ) -> list[dict[str, object]]:
        if tenant_id is None:
            result = await self._session.execute(
                text("""
                    SELECT id, job_id, worker_stream, payload, created_at
                    FROM job_dispatch_outbox
                    WHERE status = 'pending'
                    ORDER BY created_at ASC, id ASC
                    LIMIT :limit
                """),
                {"limit": limit},
            )
        else:
            result = await self._session.execute(
                text("""
                    SELECT id, job_id, worker_stream, payload, created_at
                    FROM job_dispatch_outbox
                    WHERE status = 'pending'
                      AND tenant_id = :tenant_id
                    ORDER BY created_at ASC, id ASC
                    LIMIT :limit
                """),
                {
                    "tenant_id": str(tenant_id),
                    "limit": limit,
                },
            )
        return list(result.mappings().all())

    async def _mark_outbox_error(self, outbox_id: int, error: str) -> None:
        await self._session.execute(
            text("""
                UPDATE job_dispatch_outbox
                SET last_error = :error
                WHERE id = :id
            """),
            {
                "id": outbox_id,
                "error": error[:4000],
            },
        )
        await self._session.flush()

    async def _acquire_relay_lock(self, holder: str) -> bool:
        acquired = await self._redis.set(
            _RELAY_LOCK_KEY,
            holder,
            nx=True,
            ex=_RELAY_LOCK_TTL_SECONDS,
        )
        return bool(acquired)

    async def _release_relay_lock(self, holder: str) -> bool:
        script = """
        if redis.call("GET", KEYS[1]) == ARGV[1] then
            return redis.call("DEL", KEYS[1])
        else
            return 0
        end
        """
        result = await self._redis.eval(script, 1, _RELAY_LOCK_KEY, holder)
        return int(result) == 1

    def _stream_message_id(self, created_at: object, outbox_id: int) -> str:
        if isinstance(created_at, datetime):
            milliseconds = int(created_at.timestamp() * 1000)
        else:
            parsed = datetime.fromisoformat(str(created_at))
            milliseconds = int(parsed.timestamp() * 1000)
        return f"{milliseconds}-{outbox_id}"

    async def _get_phase_number(self, phase_id: uuid.UUID) -> int:
        """Look up phase_number from phase_id."""
        result = await self._session.execute(text("""
            SELECT phase_number FROM scan_phases WHERE id = :id
        """), {"id": str(phase_id)})
        row = result.mappings().first()
        return int(row["phase_number"]) if row else 0


def _merge_configs(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_configs(merged[key], value)
        else:
            merged[key] = value
    return merged
