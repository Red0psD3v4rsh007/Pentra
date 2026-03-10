"""Pipeline executor — central DAG pipeline execution coordinator.

MOD-04.5: Encapsulates the core execution loop:

  resolve_ready_nodes() → dispatch_nodes() → update_progress()

Called by OrchestratorService after events (node completion, node failure).
Coordinates: dependency resolution, phase transitions, failure propagation,
job dispatch, and progress tracking.

This replaces inline orchestration logic with a clean, composable coordinator.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from app.engine.dependency_resolver import DependencyResolver, ReadyNode
from app.engine.job_dispatcher import JobDispatcher
from app.engine.phase_controller import PhaseController
from app.engine.state_manager import StateManager

logger = logging.getLogger(__name__)


class PipelineExecutor:
    """Coordinates the DAG pipeline execution cycle.

    Usage::

        executor = PipelineExecutor(session, redis)
        result = await executor.execute_after_completion(
            dag_id=..., scan_id=..., tenant_id=...,
            node_id=..., output_ref=..., output_summary=...,
            target=..., priority=...,
        )
    """

    def __init__(
        self,
        session: AsyncSession,
        redis: aioredis.Redis,
    ) -> None:
        self._session = session
        self._redis = redis
        self._state = StateManager(session)
        self._resolver = DependencyResolver(session)
        self._controller = PhaseController(session)
        self._dispatcher = JobDispatcher(session, redis)

    # ── After node completion ────────────────────────────────────

    async def execute_after_completion(
        self,
        *,
        dag_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        node_id: uuid.UUID,
        phase_number: int,
        output_ref: str,
        output_summary: dict | None = None,
        tool: str = "unknown",
        target: str = "",
        priority: str = "normal",
    ) -> dict[str, Any]:
        """Execute the pipeline after a node completes.

        Flow:
          1. Store artifact
          2. Resolve newly ready nodes (dependencies now satisfied)
          3. Evaluate phase → advance if complete
          4. Dispatch ready nodes
          5. Update scan progress
          6. Handle DAG completion

        Returns dict with 'dag_status', 'dispatched_count', 'progress'.
        """
        # 1 — Store artifact
        await self._state.store_artifact(
            scan_id=scan_id, node_id=node_id, tenant_id=tenant_id,
            artifact_type=tool, storage_ref=output_ref,
        )

        # 2 — Resolve newly ready nodes (pending → ready)
        newly_ready = await self._resolver.resolve_ready_nodes(dag_id)

        # 3 — Evaluate phase and advance
        dag_status, phase_ready = await self._controller.evaluate_and_advance(
            dag_id, phase_number
        )

        # Combine ready nodes from resolution + phase advancement
        all_ready = newly_ready + phase_ready

        # 4 — Dispatch all ready nodes
        dispatched = []
        if all_ready:
            dispatched = await self._dispatcher.dispatch_nodes(
                all_ready,
                scan_id=scan_id,
                tenant_id=tenant_id,
                target=target,
                priority=priority,
            )

        # 5 — Update scan progress
        progress = await self._state.update_scan_progress(scan_id)

        logger.info(
            "Pipeline after completion: dag=%s status=%s dispatched=%d progress=%d%%",
            dag_id, dag_status, len(dispatched), progress,
        )

        return {
            "dag_status": dag_status,
            "dispatched_count": len(dispatched),
            "progress": progress,
        }

    # ── After node permanent failure ─────────────────────────────

    async def execute_after_failure(
        self,
        *,
        dag_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        node_id: uuid.UUID,
        phase_number: int,
        target: str = "",
        priority: str = "normal",
    ) -> dict[str, Any]:
        """Execute the pipeline after a permanent node failure.

        Flow:
          1. Propagate failure → skip downstream dependents
          2. Resolve any remaining ready nodes
          3. Evaluate phase → advance or fail
          4. Dispatch ready nodes
          5. Update scan progress
          6. Handle DAG completion/failure

        Returns dict with 'dag_status', 'skipped_count', 'dispatched_count', 'progress'.
        """
        # 1 — Propagate failure to downstream nodes
        skipped = await self._state.propagate_failure(node_id, dag_id)

        # 2 — Resolve remaining ready nodes
        ready = await self._resolver.resolve_ready_nodes(dag_id)

        # 3 — Evaluate phase and advance
        dag_status, phase_ready = await self._controller.evaluate_and_advance(
            dag_id, phase_number
        )

        all_ready = ready + phase_ready

        # 4 — Dispatch ready nodes
        dispatched = []
        if all_ready:
            dispatched = await self._dispatcher.dispatch_nodes(
                all_ready,
                scan_id=scan_id,
                tenant_id=tenant_id,
                target=target,
                priority=priority,
            )

        # 5 — Update scan progress
        progress = await self._state.update_scan_progress(scan_id)

        logger.info(
            "Pipeline after failure: dag=%s status=%s skipped=%d dispatched=%d progress=%d%%",
            dag_id, dag_status, len(skipped), len(dispatched), progress,
        )

        return {
            "dag_status": dag_status,
            "skipped_count": len(skipped),
            "dispatched_count": len(dispatched),
            "progress": progress,
        }

    # ── Initial pipeline start ───────────────────────────────────

    async def start_pipeline(
        self,
        *,
        dag_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        target: str = "",
        priority: str = "normal",
    ) -> dict[str, Any]:
        """Activate first phase and dispatch initial nodes.

        Called once after DAG construction.

        Returns dict with 'dispatched_count'.
        """
        # Activate first phase → returns nodes already resolved to ready
        ready_nodes = await self._controller.activate_first_phase(dag_id)

        # Resolve any additional ready nodes
        more_ready = await self._resolver.resolve_ready_nodes(dag_id)
        all_ready = ready_nodes + more_ready

        # Dispatch
        dispatched = []
        if all_ready:
            dispatched = await self._dispatcher.dispatch_nodes(
                all_ready,
                scan_id=scan_id,
                tenant_id=tenant_id,
                target=target,
                priority=priority,
            )

        logger.info(
            "Pipeline started: dag=%s dispatched=%d nodes",
            dag_id, len(dispatched),
        )

        return {"dispatched_count": len(dispatched)}
