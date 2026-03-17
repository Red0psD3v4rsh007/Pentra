"""Dependency resolver — determines which DAG nodes are ready to execute.

MOD-04.5 two-step resolution:
  1. ``resolve_ready_nodes()`` — finds pending nodes whose deps are satisfied,
     transitions them pending → ready, returns ReadyNode list.
  2. ``get_ready_nodes()`` — returns nodes already in 'ready' state
     (used after resolve, or when re-checking after events).

A node is *eligible* when:
  1. Its phase is currently active (status = 'running')
  2. All incoming edges have ``data_ref IS NOT NULL`` (upstream completed)
  3. The node itself is in 'pending' status

Also evaluates phase completion using ``min_success_ratio``.
"""

from __future__ import annotations

__classification__ = "runtime_hot_path"

import logging
import uuid
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


@dataclass
class ReadyNode:
    """A node that is ready to be dispatched to a worker."""

    node_id: uuid.UUID
    dag_id: uuid.UUID
    phase_id: uuid.UUID
    tool: str
    worker_family: str
    config: dict
    input_refs: dict


class DependencyResolver:
    """Resolves node dependencies within a scan DAG."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def resolve_ready_nodes(self, dag_id: uuid.UUID) -> list[ReadyNode]:
        """Find pending nodes whose dependencies are satisfied and transition them to ready.

        Two-step flow:
          1. SELECT all pending nodes in running phases where all edges are satisfied
          2. UPDATE their status from 'pending' to 'ready'
          3. Return them as ReadyNode objects
        """
        # Find eligible nodes
        result = await self._session.execute(text("""
            SELECT n.id, n.dag_id, n.phase_id, n.tool, n.worker_family,
                   n.config, n.input_refs
            FROM scan_nodes n
            JOIN scan_phases p ON p.id = n.phase_id
            WHERE n.dag_id = :did
              AND n.status = 'pending'
              AND p.status = 'running'
              AND NOT EXISTS (
                  SELECT 1 FROM scan_edges e
                  WHERE e.target_node_id = n.id
                    AND e.data_ref IS NULL
              )
        """), {"did": str(dag_id)})

        nodes = []
        for row in result.mappings().all():
            node_id = uuid.UUID(str(row["id"]))

            # Transition pending → ready
            await self._session.execute(text("""
                UPDATE scan_nodes SET status = 'ready'
                WHERE id = :id AND status = 'pending'
            """), {"id": str(node_id)})

            nodes.append(ReadyNode(
                node_id=node_id,
                dag_id=uuid.UUID(str(row["dag_id"])),
                phase_id=uuid.UUID(str(row["phase_id"])),
                tool=row["tool"],
                worker_family=row["worker_family"],
                config=row["config"] if isinstance(row["config"], dict) else {},
                input_refs=row["input_refs"] if isinstance(row["input_refs"], dict) else {},
            ))

        if nodes:
            await self._session.flush()
            logger.info("Resolved %d ready nodes for dag %s", len(nodes), dag_id)
        return nodes

    async def get_ready_nodes(self, dag_id: uuid.UUID) -> list[ReadyNode]:
        """Return nodes already in 'ready' state (post-resolution).

        Use after ``resolve_ready_nodes()`` or when checking for nodes that
        were previously resolved but not yet dispatched.
        """
        result = await self._session.execute(text("""
            SELECT n.id, n.dag_id, n.phase_id, n.tool, n.worker_family,
                   n.config, n.input_refs
            FROM scan_nodes n
            JOIN scan_phases p ON p.id = n.phase_id
            WHERE n.dag_id = :did
              AND n.status = 'ready'
              AND p.status = 'running'
        """), {"did": str(dag_id)})

        nodes = []
        for row in result.mappings().all():
            nodes.append(ReadyNode(
                node_id=uuid.UUID(str(row["id"])),
                dag_id=uuid.UUID(str(row["dag_id"])),
                phase_id=uuid.UUID(str(row["phase_id"])),
                tool=row["tool"],
                worker_family=row["worker_family"],
                config=row["config"] if isinstance(row["config"], dict) else {},
                input_refs=row["input_refs"] if isinstance(row["input_refs"], dict) else {},
            ))

        logger.debug("Ready nodes for dag %s: %d", dag_id, len(nodes))
        return nodes

    async def check_phase_complete(
        self, dag_id: uuid.UUID, phase_number: int
    ) -> str:
        """Evaluate whether a phase is complete.

        Returns one of: 'running', 'completed', 'partial_success', 'failed'.

        Logic:
          - If any node is still running/scheduled/pending → 'running'
          - Count completed vs total nodes
          - If completed/total >= min_success_ratio → 'completed' or 'partial_success'
          - Otherwise → 'failed'
        """
        result = await self._session.execute(text("""
            SELECT
                p.min_success_ratio,
                COUNT(*) FILTER (WHERE n.status IN ('pending','scheduled','running'))
                    AS active,
                COUNT(*) FILTER (WHERE n.status = 'completed') AS completed,
                COUNT(*) FILTER (WHERE n.status = 'failed') AS failed,
                COUNT(*) FILTER (WHERE n.status = 'skipped') AS skipped,
                COUNT(*) AS total
            FROM scan_nodes n
            JOIN scan_phases p ON p.id = n.phase_id
            WHERE n.dag_id = :did AND p.phase_number = :pn
            GROUP BY p.min_success_ratio
        """), {"did": str(dag_id), "pn": phase_number})

        row = result.mappings().first()
        if row is None:
            return "completed"  # no nodes in phase

        if row["active"] > 0:
            return "running"

        total_attempted = int(row["total"]) - int(row["skipped"])
        if total_attempted == 0:
            return "completed"

        success_ratio = int(row["completed"]) / total_attempted
        min_ratio = float(row["min_success_ratio"])

        if success_ratio >= 1.0:
            return "completed"
        elif success_ratio >= min_ratio:
            return "partial_success"
        else:
            return "failed"
