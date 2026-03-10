"""Job dispatcher — creates ScanJob rows and publishes to worker streams.

Routes jobs to the correct worker-family stream:
  pentra:stream:worker:recon
  pentra:stream:worker:network
  pentra:stream:worker:web
  pentra:stream:worker:vuln
  pentra:stream:worker:exploit
"""

from __future__ import annotations

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
        """Dispatch a batch of ready nodes to their worker streams.

        For each node:
          1. Create a ScanJob row in PostgreSQL
          2. Mark the node as 'scheduled'
          3. XADD the job payload to the worker-family stream

        Returns a list of created job IDs.
        """
        job_ids: list[uuid.UUID] = []
        now = datetime.now(timezone.utc).isoformat()

        for node in nodes:
            job_id = uuid.uuid4()

            # 1 — Create ScanJob (include all NOT NULL columns)
            await self._session.execute(text("""
                INSERT INTO scan_jobs
                    (id, scan_id, tenant_id, phase, tool, status,
                     priority, max_retries, timeout_seconds)
                VALUES
                    (:id, :sid, :tid, :phase, :tool, 'queued',
                     :priority, :max_retries, :timeout)
            """), {
                "id": str(job_id), "sid": str(scan_id), "tid": str(tenant_id),
                "phase": await self._get_phase_number(node.phase_id),
                "tool": node.tool,
                "priority": priority,
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

            # 3 — Publish to worker stream
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
                "config": json.dumps(config or {}),
                "input_refs": json.dumps(node.input_refs),
                "dispatched_at": now,
            }
            await self._redis.xadd(
                stream, {"data": json.dumps(payload)},
                maxlen=_MAX_STREAM_LEN, approximate=True,
            )

            job_ids.append(job_id)

            logger.info(
                "Dispatched job %s: tool=%s → stream=%s (scan=%s node=%s)",
                job_id, node.tool, stream, scan_id, node.node_id,
            )

        await self._session.flush()
        return job_ids

    async def _get_phase_number(self, phase_id: uuid.UUID) -> int:
        """Look up phase_number from phase_id."""
        result = await self._session.execute(text("""
            SELECT phase_number FROM scan_phases WHERE id = :id
        """), {"id": str(phase_id)})
        row = result.mappings().first()
        return int(row["phase_number"]) if row else 0
