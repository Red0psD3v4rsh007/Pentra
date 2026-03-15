"""State manager — tracks scan, DAG, phase, and node state transitions.

Node state machine (MOD-04.5):
  pending → ready       Dependencies satisfied
  ready → running       Worker picked up job
  running → completed   Tool finished successfully
  running → failed      Tool error (may retry)
  running → blocked     Blocked on new dependency (retry path)
  blocked → ready       Dependency satisfied, can re-dispatch
  pending → skipped     Upstream permanently failed

Handles:
  - Node lifecycle transitions with guard validation
  - Failure propagation: cascade-skip downstream dependents
  - Scan-level progress calculation (completed + skipped = resolved)
  - Scan status transitions (queued → validating → running → ...)
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.storage.retention import apply_artifact_retention_metadata

logger = logging.getLogger(__name__)

# ── Valid node state transitions ─────────────────────────────────────

_NODE_TRANSITIONS: dict[str, set[str]] = {
    "pending":   {"ready", "skipped"},
    "ready":     {"scheduled", "running"},
    "scheduled": {"running"},
    "running":   {"completed", "failed", "blocked"},
    "blocked":   {"ready"},
    "failed":    {"pending"},  # retry path only
}

# ── Valid scan status transitions ────────────────────────────────────

_SCAN_TRANSITIONS: dict[str, set[str]] = {
    "queued":      {"validating", "cancelled", "failed"},
    "validating":  {"running", "failed", "cancelled"},
    "running":     {"running", "analyzing", "paused", "failed", "cancelled", "completed"},
    "paused":      {"running", "cancelled"},
    "analyzing":   {"reporting", "failed"},
    "reporting":   {"completed", "failed"},
}


class StateManager:
    """Manages state transitions for scan nodes, phases, and overall scans."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ── Node state ───────────────────────────────────────────────

    async def mark_node_ready(self, node_id: uuid.UUID) -> None:
        """Transition a node from pending → ready (dependencies satisfied)."""
        await self._transition_node(node_id, from_status="pending", to_status="ready")
        logger.debug("Node %s → ready", node_id)

    async def mark_node_scheduled(self, node_id: uuid.UUID) -> None:
        """Mark a node as scheduled (dispatched to worker stream)."""
        await self._transition_node(node_id, from_status="ready", to_status="scheduled")

    async def mark_node_running(self, node_id: uuid.UUID) -> None:
        """Mark a node as running (worker picked up the job)."""
        await self._session.execute(text("""
            UPDATE scan_nodes SET status = 'running'
            WHERE id = :id AND status IN ('scheduled', 'ready')
        """), {"id": str(node_id)})
        await self._session.execute(text("""
            UPDATE scan_jobs
            SET status = 'running', started_at = COALESCE(started_at, NOW())
            WHERE id = (SELECT job_id FROM scan_nodes WHERE id = :nid)
        """), {"nid": str(node_id)})

    async def mark_node_completed(
        self,
        node_id: uuid.UUID,
        output_ref: str,
        output_summary: dict | None = None,
    ) -> dict:
        """Mark a node as completed and propagate data to downstream edges.

        Returns dict with dag_id and phase_number for phase evaluation.
        """
        import json
        summary_json = json.dumps(output_summary or {})
        await self._session.execute(text("""
            UPDATE scan_nodes
            SET status = 'completed',
                output_ref = :ref, output_summary = CAST(:summary AS jsonb)
            WHERE id = :id
        """), {
            "id": str(node_id),
            "ref": output_ref,
            "summary": summary_json,
        })

        await self._session.execute(text("""
            UPDATE scan_jobs
            SET status = 'completed',
                completed_at = NOW(),
                output_ref = :ref
            WHERE id = (SELECT job_id FROM scan_nodes WHERE id = :nid)
        """), {"ref": output_ref, "nid": str(node_id)})

        # Propagate data_ref to all outgoing edges
        await self._session.execute(text("""
            UPDATE scan_edges SET data_ref = :ref
            WHERE source_node_id = :nid
        """), {"ref": output_ref, "nid": str(node_id)})

        # Get DAG and phase info for this node
        result = await self._session.execute(text("""
            SELECT n.dag_id, p.phase_number
            FROM scan_nodes n JOIN scan_phases p ON p.id = n.phase_id
            WHERE n.id = :id
        """), {"id": str(node_id)})
        row = result.mappings().first()

        await self._session.flush()

        logger.info("Node %s COMPLETED, output_ref=%s", node_id, output_ref)
        return {
            "dag_id": uuid.UUID(str(row["dag_id"])) if row else None,
            "phase_number": int(row["phase_number"]) if row else None,
        }

    async def mark_node_failed(
        self, node_id: uuid.UUID, error: str
    ) -> dict:
        """Mark a node as failed.

        Returns dict with dag_id, phase_number, retry_count, max_retries.
        Retry info comes from the linked scan_jobs row.
        """
        await self._session.execute(text("""
            UPDATE scan_nodes SET status = 'failed'
            WHERE id = :id
        """), {"id": str(node_id)})

        # Get DAG/phase info from node + retry info from linked job
        result = await self._session.execute(text("""
            SELECT n.dag_id, p.phase_number,
                   COALESCE(j.retry_count, 0) AS retry_count,
                   COALESCE(j.max_retries, 0) AS max_retries
            FROM scan_nodes n
            JOIN scan_phases p ON p.id = n.phase_id
            LEFT JOIN scan_jobs j ON j.id = n.job_id
            WHERE n.id = :id
        """), {"id": str(node_id)})
        row = result.mappings().first()

        # Also update the linked job's error
        await self._session.execute(text("""
            UPDATE scan_jobs
            SET status = 'failed', error_message = :err,
                completed_at = NOW()
            WHERE id = (SELECT job_id FROM scan_nodes WHERE id = :nid)
        """), {"err": error, "nid": str(node_id)})

        await self._session.flush()

        logger.warning("Node %s FAILED: %s", node_id, error)
        return {
            "dag_id": uuid.UUID(str(row["dag_id"])) if row else None,
            "phase_number": int(row["phase_number"]) if row else None,
            "retry_count": int(row["retry_count"]) if row else 0,
            "max_retries": int(row["max_retries"]) if row else 0,
        }

    async def reset_node_for_retry(self, node_id: uuid.UUID) -> None:
        """Reset a failed node back to pending for retry."""
        await self._session.execute(text("""
            UPDATE scan_nodes SET status = 'pending'
            WHERE id = :id
        """), {"id": str(node_id)})

        # Increment retry count on the linked job
        await self._session.execute(text("""
            UPDATE scan_jobs
            SET status = 'queued', retry_count = retry_count + 1,
                started_at = NULL, completed_at = NULL, error_message = NULL
            WHERE id = (SELECT job_id FROM scan_nodes WHERE id = :nid)
        """), {"nid": str(node_id)})

        await self._session.flush()
        logger.info("Node %s reset for retry", node_id)

    async def mark_node_skipped(
        self, node_id: uuid.UUID, reason: str = "upstream_failed"
    ) -> None:
        """Mark a pending node as skipped (upstream permanently failed)."""
        await self._session.execute(text("""
            UPDATE scan_nodes SET status = 'skipped'
            WHERE id = :id AND status = 'pending'
        """), {"id": str(node_id)})
        logger.info("Node %s SKIPPED: %s", node_id, reason)

    async def mark_node_blocked(self, node_id: uuid.UUID) -> None:
        """Mark a running node as blocked (waiting for re-resolved dep)."""
        await self._transition_node(node_id, from_status="running", to_status="blocked")
        logger.info("Node %s → blocked", node_id)

    async def unblock_node(self, node_id: uuid.UUID) -> None:
        """Transition a blocked node back to ready."""
        await self._transition_node(node_id, from_status="blocked", to_status="ready")
        logger.info("Node %s → ready (unblocked)", node_id)

    async def propagate_failure(
        self, node_id: uuid.UUID, dag_id: uuid.UUID
    ) -> list[uuid.UUID]:
        """Cascade-skip all downstream dependents of a permanently failed node.

        Walks the scan_edges graph starting from node_id, marking every
        reachable pending node as 'skipped'.  Returns list of skipped node IDs.
        """
        skipped: list[uuid.UUID] = []
        frontier = [node_id]

        while frontier:
            current = frontier.pop()

            # Find all direct downstream nodes that are still pending
            result = await self._session.execute(text("""
                SELECT DISTINCT e.target_node_id
                FROM scan_edges e
                JOIN scan_nodes n ON n.id = e.target_node_id
                WHERE e.source_node_id = :nid
                  AND e.dag_id = :did
                  AND n.status = 'pending'
            """), {"nid": str(current), "did": str(dag_id)})

            for row in result.mappings().all():
                child_id = uuid.UUID(str(row["target_node_id"]))
                await self.mark_node_skipped(child_id, reason=f"upstream {current} failed")
                skipped.append(child_id)
                frontier.append(child_id)  # continue cascading

        if skipped:
            logger.info(
                "Failure propagation from %s: %d nodes skipped",
                node_id, len(skipped),
            )
        return skipped

    async def _transition_node(
        self, node_id: uuid.UUID, *, from_status: str, to_status: str
    ) -> None:
        """Generic guarded node state transition."""
        result = await self._session.execute(text("""
            UPDATE scan_nodes SET status = :to_st
            WHERE id = :id AND status = :from_st
            RETURNING id
        """), {"id": str(node_id), "from_st": from_status, "to_st": to_status})
        if result.rowcount == 0:
            logger.warning(
                "Node %s transition %s→%s failed (not in expected state)",
                node_id, from_status, to_status,
            )

    # ── Scan state ───────────────────────────────────────────────

    async def transition_scan(
        self, scan_id: uuid.UUID, new_status: str
    ) -> str | None:
        """Transition the scan to a new status if the transition is valid.

        Returns the old status, or None if transition was rejected.
        """
        result = await self._session.execute(text("""
            SELECT status FROM scans WHERE id = :id
        """), {"id": str(scan_id)})
        row = result.mappings().first()
        if row is None:
            return None

        old_status = row["status"]
        allowed = _SCAN_TRANSITIONS.get(old_status, set())
        if new_status not in allowed:
            logger.warning(
                "Invalid scan transition: %s → %s (scan=%s)",
                old_status, new_status, scan_id,
            )
            return None

        if new_status in ("completed", "failed", "cancelled"):
            await self._session.execute(text("""
                UPDATE scans SET status = :st, completed_at = NOW()
                WHERE id = :id
            """), {"st": new_status, "id": str(scan_id)})
        else:
            await self._session.execute(text("""
                UPDATE scans SET status = :st WHERE id = :id
            """), {"st": new_status, "id": str(scan_id)})

        await self._session.flush()
        logger.info("Scan %s: %s → %s", scan_id, old_status, new_status)
        return old_status

    async def update_scan_progress(self, scan_id: uuid.UUID) -> int:
        """Recalculate and update scan progress percentage.

        Progress = (completed + skipped) / total * 100
        """
        result = await self._session.execute(text("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE n.status IN ('completed', 'skipped')) AS resolved
            FROM scan_nodes n
            JOIN scan_dags d ON d.id = n.dag_id
            WHERE d.scan_id = :sid
        """), {"sid": str(scan_id)})
        row = result.mappings().first()
        if row is None or int(row["total"]) == 0:
            return 0

        progress = int(int(row["resolved"]) / int(row["total"]) * 100)
        await self._session.execute(text("""
            UPDATE scans SET progress = :p WHERE id = :id
        """), {"p": progress, "id": str(scan_id)})
        await self._session.flush()
        return progress

    # ── Artifact tracking ────────────────────────────────────────

    async def store_artifact(
        self,
        *,
        scan_id: uuid.UUID,
        node_id: uuid.UUID,
        tenant_id: uuid.UUID,
        artifact_type: str,
        storage_ref: str,
        content_type: str = "application/json",
        size_bytes: int = 0,
        checksum: str | None = None,
        metadata: dict | None = None,
    ) -> uuid.UUID:
        """Record a scan artifact produced by a node.

        These artifacts feed the future Attack Graph Engine.
        """
        aid = uuid.uuid4()
        import json
        metadata_payload = apply_artifact_retention_metadata(metadata)

        await self._session.execute(text("""
            INSERT INTO scan_artifacts (id, scan_id, node_id, tenant_id,
                                        artifact_type, storage_ref, content_type,
                                        size_bytes, checksum, metadata)
            VALUES (:id, :sid, :nid, :tid, :type, :ref, :content_type,
                    :size, :checksum, CAST(:metadata AS jsonb))
        """), {
            "id": str(aid), "sid": str(scan_id), "nid": str(node_id),
            "tid": str(tenant_id), "type": artifact_type,
            "ref": storage_ref, "content_type": content_type, "size": size_bytes,
            "checksum": checksum, "metadata": json.dumps(metadata_payload),
        })
        await self._session.flush()
        logger.info("Artifact stored: %s type=%s ref=%s", aid, artifact_type, storage_ref)
        return aid
