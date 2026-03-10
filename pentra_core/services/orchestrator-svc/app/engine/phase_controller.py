"""Phase controller — manages phase lifecycle and progression.

Responsible for:
  - Activating the first phase of a newly-built DAG
  - Evaluating phase completion (using DependencyResolver)
  - Transitioning to the next phase
  - Determining when the entire DAG is complete
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.engine.dependency_resolver import DependencyResolver, ReadyNode

logger = logging.getLogger(__name__)


class PhaseController:
    """Controls phase progression within a scan DAG."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._resolver = DependencyResolver(session)

    async def activate_first_phase(self, dag_id: uuid.UUID) -> list[ReadyNode]:
        """Activate phase 0 (or the first defined phase) and return ready nodes.

        Called after DAG construction to kick off execution.
        """
        # Find the lowest phase_number in this DAG
        result = await self._session.execute(text("""
            SELECT id, phase_number FROM scan_phases
            WHERE dag_id = :did
            ORDER BY phase_number ASC
            LIMIT 1
        """), {"did": str(dag_id)})

        row = result.mappings().first()
        if row is None:
            logger.warning("No phases in DAG %s", dag_id)
            return []

        phase_id = row["id"]
        phase_num = row["phase_number"]

        # Mark phase as running
        # now = datetime.now(timezone.utc).isoformat()
        now = datetime.now(timezone.utc)
        await self._session.execute(text("""
            UPDATE scan_phases SET status = 'running', started_at = :now
            WHERE id = :pid
        """), {"pid": str(phase_id), "now": now})

        # Mark DAG as executing
        await self._session.execute(text("""
            UPDATE scan_dags SET status = 'executing', current_phase = :pn
            WHERE id = :did
        """), {"did": str(dag_id), "pn": phase_num})

        await self._session.flush()

        logger.info("Activated phase %d for DAG %s", phase_num, dag_id)
        return await self._resolver.resolve_ready_nodes(dag_id)

    async def evaluate_and_advance(
        self, dag_id: uuid.UUID, current_phase: int
    ) -> tuple[str, list[ReadyNode]]:
        """Evaluate the current phase and advance if complete.

        Returns:
            (dag_status, ready_nodes) where dag_status is one of:
            'executing' — more work to do (ready_nodes may be non-empty)
            'completed' — all phases done
            'failed' — unrecoverable phase failure
        """
        phase_status = await self._resolver.check_phase_complete(
            dag_id, current_phase
        )

        if phase_status == "running":
            # Phase still has active nodes — check for more ready nodes
            ready = await self._resolver.resolve_ready_nodes(dag_id)
            return "executing", ready

        # Phase is done — mark it
        # now = datetime.now(timezone.utc).isoformat()
        now = datetime.now(timezone.utc)
        await self._session.execute(text("""
            UPDATE scan_phases SET status = :st, completed_at = :now
            WHERE dag_id = :did AND phase_number = :pn
        """), {
            "st": phase_status, "did": str(dag_id),
            "pn": current_phase, "now": now,
        })

        if phase_status == "failed":
            # Phase failed below min_success_ratio — fail the DAG
            await self._session.execute(text("""
                UPDATE scan_dags SET status = 'failed' WHERE id = :did
            """), {"did": str(dag_id)})
            await self._session.flush()
            logger.error("Phase %d FAILED for DAG %s", current_phase, dag_id)
            return "failed", []

        # Phase completed or partial_success — try to advance
        logger.info(
            "Phase %d %s for DAG %s — advancing",
            current_phase, phase_status, dag_id,
        )

        # Find next phase
        result = await self._session.execute(text("""
            SELECT id, phase_number FROM scan_phases
            WHERE dag_id = :did AND phase_number > :pn
            ORDER BY phase_number ASC
            LIMIT 1
        """), {"did": str(dag_id), "pn": current_phase})

        next_phase = result.mappings().first()
        if next_phase is None:
            # No more phases — DAG is complete
            await self._session.execute(text("""
                UPDATE scan_dags SET status = 'completed' WHERE id = :did
            """), {"did": str(dag_id)})
            await self._session.flush()
            logger.info("DAG %s COMPLETED (all phases done)", dag_id)
            return "completed", []

        # Activate next phase
        next_id = next_phase["id"]
        next_num = next_phase["phase_number"]

        await self._session.execute(text("""
            UPDATE scan_phases SET status = 'running', started_at = :now
            WHERE id = :pid
        """), {"pid": str(next_id), "now": now})

        await self._session.execute(text("""
            UPDATE scan_dags SET current_phase = :pn WHERE id = :did
        """), {"did": str(dag_id), "pn": next_num})

        await self._session.flush()

        logger.info("Advanced to phase %d for DAG %s", next_num, dag_id)
        ready = await self._resolver.resolve_ready_nodes(dag_id)
        return "executing", ready
