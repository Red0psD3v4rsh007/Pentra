"""State manager — tracks scan, DAG, phase, and node state transitions.

Handles:
  - Node completion: update status, populate edge data_refs, store artifacts
  - Node/job failure: route retry decisions through scan_jobs table
  - Scan-level progress calculation
  - Scan status transitions (queued → validating → running → ...)
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# ── Valid scan status transitions ────────────────────────────────────

_SCAN_TRANSITIONS: dict[str, set[str]] = {
    "queued":      {"validating", "cancelled", "failed"},
    "validating":  {"running", "failed", "cancelled"},
    "running":     {"running", "analyzing", "paused", "failed", "cancelled"},
    "paused":      {"running", "cancelled"},
    "analyzing":   {"reporting", "failed"},
    "reporting":   {"completed", "failed"},
}


class StateManager:
    """Manages state transitions for scan nodes, phases, and overall scans."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ── Node state ───────────────────────────────────────────────

    async def mark_node_scheduled(self, node_id: uuid.UUID) -> None:
        """Mark a node as scheduled (dispatched to worker stream)."""
        await self._session.execute(text("""
            UPDATE scan_nodes SET status = 'scheduled'
            WHERE id = :id AND status = 'pending'
        """), {"id": str(node_id)})

    async def mark_node_running(self, node_id: uuid.UUID) -> None:
        """Mark a node as running (worker picked up the job)."""
        await self._session.execute(text("""
            UPDATE scan_nodes SET status = 'running'
            WHERE id = :id AND status = 'scheduled'
        """), {"id": str(node_id)})

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
        """Recalculate and update scan progress percentage."""
        result = await self._session.execute(text("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE n.status = 'completed') AS done
            FROM scan_nodes n
            JOIN scan_dags d ON d.id = n.dag_id
            WHERE d.scan_id = :sid
        """), {"sid": str(scan_id)})
        row = result.mappings().first()
        if row is None or int(row["total"]) == 0:
            return 0

        progress = int(int(row["done"]) / int(row["total"]) * 100)
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
        size_bytes: int = 0,
    ) -> uuid.UUID:
        """Record a scan artifact produced by a node.

        These artifacts feed the future Attack Graph Engine.
        """
        aid = uuid.uuid4()
        await self._session.execute(text("""
            INSERT INTO scan_artifacts (id, scan_id, node_id, tenant_id,
                                        artifact_type, storage_ref, size_bytes)
            VALUES (:id, :sid, :nid, :tid, :type, :ref, :size)
        """), {
            "id": str(aid), "sid": str(scan_id), "nid": str(node_id),
            "tid": str(tenant_id), "type": artifact_type,
            "ref": storage_ref, "size": size_bytes,
        })
        await self._session.flush()
        logger.info("Artifact stored: %s type=%s ref=%s", aid, artifact_type, storage_ref)
        return aid
