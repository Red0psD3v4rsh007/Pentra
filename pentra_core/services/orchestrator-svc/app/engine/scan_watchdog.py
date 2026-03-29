"""Scan watchdog — detects and recovers stale scans.

Runs as an asyncio background task within the orchestrator.
Every POLL_INTERVAL_SECONDS it checks for:

  1. Scans stuck in 'running' / 'validating' with no node activity
     for longer than STALE_SCAN_TIMEOUT_MINUTES.
  2. Individual nodes stuck in 'scheduled' or 'running' longer than
     STALE_NODE_TIMEOUT_MINUTES.

Recovery actions:
  - Stale nodes: marked as 'failed' with error WATCHDOG_TIMEOUT.
  - Phase evaluation triggered after marking stale nodes.
  - Scans with ALL nodes terminal and no activity: force-completed/failed.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.engine.job_dispatcher import JobDispatcher

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────

POLL_INTERVAL_SECONDS = int(os.getenv("WATCHDOG_POLL_INTERVAL", "60"))
STALE_SCAN_TIMEOUT_MINUTES = int(os.getenv("WATCHDOG_STALE_SCAN_MINUTES", "15"))
STALE_NODE_TIMEOUT_MINUTES = int(os.getenv("WATCHDOG_STALE_NODE_MINUTES", "10"))
ENABLED = os.getenv("WATCHDOG_ENABLED", "true").strip().lower() in {"1", "true", "yes"}


class ScanWatchdog:
    """Background task that detects and recovers stale scans and nodes.

    Usage::

        watchdog = ScanWatchdog(session_factory, redis)
        task = asyncio.create_task(watchdog.start())
        # ... on shutdown:
        watchdog.stop()
        await task
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        redis: aioredis.Redis,
    ) -> None:
        self._session_factory = session_factory
        self._redis = redis
        self._running = False

    async def start(self) -> None:
        """Start the watchdog loop. Blocks until stop() is called."""
        if not ENABLED:
            logger.info("ScanWatchdog disabled via WATCHDOG_ENABLED=false")
            return

        self._running = True
        logger.info(
            "ScanWatchdog started: poll=%ds stale_scan=%dm stale_node=%dm",
            POLL_INTERVAL_SECONDS,
            STALE_SCAN_TIMEOUT_MINUTES,
            STALE_NODE_TIMEOUT_MINUTES,
        )

        while self._running:
            try:
                await self._tick()
            except asyncio.CancelledError:
                logger.info("ScanWatchdog cancelled")
                break
            except Exception:
                logger.exception("ScanWatchdog tick failed")

            try:
                await asyncio.sleep(POLL_INTERVAL_SECONDS)
            except asyncio.CancelledError:
                break

        logger.info("ScanWatchdog stopped")

    def stop(self) -> None:
        self._running = False

    async def _tick(self) -> None:
        """Single watchdog pass: recover pending dispatches, then stale work."""
        recovered_dispatches = await self._recover_pending_dispatches()
        stale_nodes = await self._recover_stale_nodes()
        stale_scans = await self._recover_stale_scans()

        if recovered_dispatches or stale_nodes or stale_scans:
            logger.warning(
                "Watchdog recovered: %d pending dispatches, %d stale nodes, %d stale scans",
                recovered_dispatches,
                stale_nodes,
                stale_scans,
            )

    async def _recover_pending_dispatches(self) -> int:
        """Flush committed job dispatches stranded before Redis publication."""
        async with self._session_factory() as session:
            dispatcher = JobDispatcher(session, self._redis)
            published = await dispatcher.publish_pending_jobs(limit=100)
            if published:
                await session.commit()
                logger.warning(
                    "Watchdog published %d pending job dispatches from DB outbox",
                    published,
                )
            return published

    # ── Stale Node Recovery ──────────────────────────────────────

    async def _recover_stale_nodes(self) -> int:
        """Find and fail nodes stuck in 'scheduled' or 'running' too long.

        A node is stale if its linked scan_job has started_at older than
        STALE_NODE_TIMEOUT_MINUTES and hasn't completed.
        """
        recovered = 0

        async with self._session_factory() as session:
            # Find stale nodes: scheduled or running with old started_at
            result = await session.execute(text("""
                SELECT n.id AS node_id,
                       n.dag_id,
                       n.status AS node_status,
                       n.tool,
                       j.id AS job_id,
                       j.scan_id,
                       j.tenant_id,
                       j.started_at,
                       d.scan_id AS dag_scan_id
                FROM scan_nodes n
                JOIN scan_jobs j ON j.id = n.job_id
                JOIN scan_dags d ON d.id = n.dag_id
                WHERE n.status IN ('scheduled', 'running')
                  AND j.started_at IS NOT NULL
                  AND j.started_at < NOW() - INTERVAL ':timeout minutes'
                  AND j.status NOT IN ('completed', 'failed')
                ORDER BY j.started_at ASC
                LIMIT 50
            """.replace(":timeout", str(STALE_NODE_TIMEOUT_MINUTES))))

            stale_rows = result.mappings().all()

            if not stale_rows:
                return 0

            logger.warning(
                "Watchdog found %d stale nodes (>%d min old)",
                len(stale_rows), STALE_NODE_TIMEOUT_MINUTES,
            )

            for row in stale_rows:
                node_id = str(row["node_id"])
                job_id = str(row["job_id"])
                tool = row["tool"]
                scan_id = str(row.get("scan_id") or row.get("dag_scan_id", ""))

                try:
                    # Fail the node
                    await session.execute(text("""
                        UPDATE scan_nodes SET status = 'failed'
                        WHERE id = :nid AND status IN ('scheduled', 'running')
                    """), {"nid": node_id})

                    # Fail the job
                    await session.execute(text("""
                        UPDATE scan_jobs
                        SET status = 'failed',
                            error_message = 'WATCHDOG_TIMEOUT: Node exceeded stale timeout',
                            completed_at = NOW()
                        WHERE id = :jid AND status NOT IN ('completed', 'failed')
                    """), {"jid": job_id})

                    recovered += 1
                    logger.warning(
                        "Watchdog failed stale node %s (tool=%s, scan=%s)",
                        node_id, tool, scan_id,
                    )

                    # Emit job.failed event so orchestrator can handle failure propagation
                    await self._emit_watchdog_failure(
                        node_id=node_id,
                        job_id=job_id,
                        scan_id=scan_id,
                        tenant_id=str(row["tenant_id"]),
                        dag_id=str(row["dag_id"]),
                        tool=tool,
                    )

                except Exception:
                    logger.exception(
                        "Watchdog failed to recover node %s", node_id,
                    )

            await session.commit()

        return recovered

    # ── Stale Scan Recovery ──────────────────────────────────────

    async def _recover_stale_scans(self) -> int:
        """Find scans stuck in running/validating with no active nodes.

        A scan is stale if:
          - status is 'running' or 'validating'
          - It has been in that state longer than STALE_SCAN_TIMEOUT_MINUTES
          - ALL its nodes are in terminal states (no pending/ready/scheduled/running)
        """
        recovered = 0

        async with self._session_factory() as session:
            result = await session.execute(text("""
                SELECT s.id AS scan_id,
                       s.tenant_id,
                       s.status,
                       s.created_at,
                       COUNT(*) AS total_nodes,
                       COUNT(*) FILTER (
                           WHERE n.status IN ('pending', 'ready', 'scheduled', 'running')
                       ) AS active_nodes,
                       COUNT(*) FILTER (WHERE n.status = 'completed') AS completed_nodes,
                       COUNT(*) FILTER (WHERE n.status = 'failed') AS failed_nodes,
                       COUNT(*) FILTER (WHERE n.status = 'skipped') AS skipped_nodes
                FROM scans s
                JOIN scan_dags d ON d.scan_id = s.id
                JOIN scan_nodes n ON n.dag_id = d.id
                WHERE s.status IN ('running', 'validating')
                  AND s.created_at < NOW() - INTERVAL ':timeout minutes'
                GROUP BY s.id
                HAVING COUNT(*) FILTER (
                    WHERE n.status IN ('pending', 'ready', 'scheduled', 'running')
                ) = 0
                LIMIT 20
            """.replace(":timeout", str(STALE_SCAN_TIMEOUT_MINUTES))))

            stale_scans = result.mappings().all()

            if not stale_scans:
                return 0

            for row in stale_scans:
                scan_id = str(row["scan_id"])
                tenant_id = str(row["tenant_id"])
                total = int(row["total_nodes"])
                completed = int(row["completed_nodes"])
                failed = int(row["failed_nodes"])
                skipped = int(row["skipped_nodes"])

                # Determine final status
                if completed > 0 and failed == 0:
                    final_status = "completed"
                elif completed > 0:
                    final_status = "completed"  # partial success is still completed
                else:
                    final_status = "failed"

                try:
                    # Update scan status
                    await session.execute(text("""
                        UPDATE scans
                        SET status = :status, completed_at = NOW(),
                            progress = 100
                        WHERE id = :sid AND status IN ('running', 'validating')
                    """), {"status": final_status, "sid": scan_id})

                    # Update DAG status
                    await session.execute(text("""
                        UPDATE scan_dags
                        SET status = :status
                        WHERE scan_id = :sid AND status NOT IN ('completed', 'failed')
                    """), {"status": final_status, "sid": scan_id})

                    # Update any remaining non-terminal phases
                    await session.execute(text("""
                        UPDATE scan_phases
                        SET status = CASE
                            WHEN status = 'running' THEN :status
                            ELSE status
                        END,
                        completed_at = COALESCE(completed_at, NOW())
                        WHERE dag_id IN (SELECT id FROM scan_dags WHERE scan_id = :sid)
                          AND status = 'running'
                    """), {"status": final_status, "sid": scan_id})

                    # Keep the DB quota row authoritative for active scan counts.
                    await session.execute(text("""
                        UPDATE tenant_quotas
                        SET active_scans = GREATEST(active_scans - 1, 0),
                            updated_at = NOW()
                        WHERE tenant_id = :tid
                    """), {"tid": tenant_id})

                    recovered += 1
                    logger.warning(
                        "Watchdog force-%s scan %s "
                        "(total=%d completed=%d failed=%d skipped=%d)",
                        final_status, scan_id,
                        total, completed, failed, skipped,
                    )

                except Exception:
                    logger.exception(
                        "Watchdog failed to recover scan %s", scan_id,
                    )

            await session.commit()

        return recovered

    # ── Event Emission ───────────────────────────────────────────

    async def _emit_watchdog_failure(
        self,
        *,
        node_id: str,
        job_id: str,
        scan_id: str,
        tenant_id: str,
        dag_id: str,
        tool: str,
    ) -> None:
        """Emit a job.failed event for a watchdog-recovered node.

        This ensures the normal failure propagation pipeline runs
        (skip downstream, evaluate phase, etc.).
        """
        import json

        payload = {
            "event_type": "job.failed",
            "event_id": str(uuid.uuid4()),
            "job_id": job_id,
            "scan_id": scan_id,
            "tenant_id": tenant_id,
            "node_id": node_id,
            "dag_id": dag_id,
            "tool": tool,
            "error_code": "WATCHDOG_TIMEOUT",
            "error_message": (
                f"Node timed out after {STALE_NODE_TIMEOUT_MINUTES} minutes "
                "with no completion event — recovered by ScanWatchdog"
            ),
            "target": "",
            "priority": "normal",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            await self._redis.xadd(
                "pentra:stream:job_events",
                {"data": json.dumps(payload, default=str)},
                maxlen=100_000,
                approximate=True,
            )
            logger.info(
                "Watchdog emitted job.failed for node %s (scan=%s)",
                node_id, scan_id,
            )
        except Exception:
            logger.exception(
                "Watchdog failed to emit failure event for node %s", node_id,
            )
