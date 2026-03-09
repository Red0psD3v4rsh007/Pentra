"""Orchestrator service — facade coordinating all engine components.

This is the central entry point for scan orchestration logic.
It wires together:
  DAGBuilder → PhaseController → JobDispatcher → StateManager

And handles the full lifecycle:
  scan.created → build DAG → dispatch phase 0
  job.completed → update state → advance phase → dispatch next
  job.failed → retry / fail → evaluate phase → advance or fail
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.engine.concurrency_controller import ConcurrencyController
from app.engine.dag_builder import DAGBuilder
from app.engine.dependency_resolver import DependencyResolver
from app.engine.job_dispatcher import JobDispatcher
from app.engine.phase_controller import PhaseController
from app.engine.retry_manager import RetryManager
from app.engine.state_manager import StateManager

logger = logging.getLogger(__name__)


class OrchestratorService:
    """Facade orchestrating the scan execution pipeline.

    Usage::

        svc = OrchestratorService(session_factory, redis)
        await svc.handle_scan_created(event)       # from ScanConsumer
        await svc.handle_job_completed(event)       # from JobEventHandler
        await svc.handle_job_failed(event)          # from JobEventHandler
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        redis: aioredis.Redis,
    ) -> None:
        self._session_factory = session_factory
        self._redis = redis
        self._concurrency = ConcurrencyController(redis)
        self._retry_mgr = RetryManager()

    # ── scan.created ─────────────────────────────────────────────

    async def handle_scan_created(self, event: dict[str, Any]) -> None:
        """Handle a scan.created event from the API gateway.

        1. Dedup event (idempotency check)
        2. Acquire distributed lock
        3. Build DAG
        4. Activate first phase
        5. Dispatch ready nodes
        6. Update scan status: queued → validating
        """
        event_id = event.get("event_id", "")
        scan_id = uuid.UUID(event["scan_id"])
        tenant_id = uuid.UUID(event["tenant_id"])
        scan_type = event["scan_type"]
        asset_type = event.get("asset_type", "web_app")
        target = event.get("target", "")
        config = event.get("config", {})

        # Idempotency
        if await self._concurrency.is_event_processed(event_id):
            logger.info("Event %s already processed — skipping", event_id)
            return

        # Distributed lock
        if not await self._concurrency.acquire_scan_lock(scan_id):
            logger.warning("Cannot acquire lock for scan %s — skipping", scan_id)
            return

        try:
            async with self._session_factory() as session:
                # Set tenant context for RLS
                from sqlalchemy import text
                await session.execute(
                    text(f"SET LOCAL app.tenant_id = '{tenant_id}'")
                )

                # 0 — Validate scan exists (retry for event-before-commit race)
                scan_found = False
                for attempt in range(4):  # up to ~3s total wait
                    scan_check = await session.execute(
                        text("SELECT id FROM scans WHERE id = :sid"),
                        {"sid": str(scan_id)},
                    )
                    if scan_check.scalar() is not None:
                        scan_found = True
                        break
                    if attempt < 3:
                        import asyncio
                        logger.debug(
                            "Scan %s not yet visible (attempt %d), waiting 1s...",
                            scan_id, attempt,
                        )
                        await asyncio.sleep(1)

                if not scan_found:
                    logger.warning(
                        "Scan %s not found after retries — stale event, skipping",
                        scan_id,
                    )
                    await self._concurrency.mark_event_processed(event_id)
                    return

                # 1 — Build DAG
                builder = DAGBuilder(session)
                dag_id = await builder.build_dag(
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    scan_type=scan_type,
                    asset_type=asset_type,
                    config=config,
                )

                # 2 — Activate first phase
                controller = PhaseController(session)
                ready_nodes = await controller.activate_first_phase(dag_id)

                # 3 — Dispatch ready nodes
                dispatcher = JobDispatcher(session, self._redis)
                if ready_nodes:
                    await dispatcher.dispatch_nodes(
                        ready_nodes,
                        scan_id=scan_id,
                        tenant_id=tenant_id,
                        target=target,
                        config=config,
                    )

                # 4 — Transition scan status
                state = StateManager(session)
                await state.transition_scan(scan_id, "validating")

                # Track tenant concurrency
                await self._concurrency.increment_tenant_scans(tenant_id)

                await session.commit()

            # Mark event as processed
            await self._concurrency.mark_event_processed(event_id)

            logger.info(
                "Scan orchestration started: scan=%s dag=%s type=%s nodes=%d",
                scan_id, dag_id, scan_type, len(ready_nodes),
            )

        except Exception:
            logger.exception("Failed to handle scan.created for %s", scan_id)
            raise
        finally:
            await self._concurrency.release_scan_lock(scan_id)

    # ── job.completed ────────────────────────────────────────────

    async def handle_job_completed(self, event: dict[str, Any]) -> None:
        """Handle a job.completed event from a worker.

        1. Mark node as completed
        2. Store artifact reference
        3. Evaluate phase
        4. If phase done → advance to next phase → dispatch new nodes
        5. If DAG done → transition scan to completed
        """
        event_id = event.get("event_id", "")
        scan_id = uuid.UUID(event["scan_id"])
        tenant_id = uuid.UUID(event["tenant_id"])
        node_id = uuid.UUID(event["node_id"]) if event.get("node_id") else None
        output_ref = event.get("output_ref", "")
        output_summary = event.get("output_summary", {})

        if await self._concurrency.is_event_processed(event_id):
            return

        if not node_id:
            logger.warning("job.completed missing node_id — skipping")
            return

        if not await self._concurrency.acquire_scan_lock(scan_id):
            logger.warning("Cannot acquire lock for scan %s", scan_id)
            return

        try:
            async with self._session_factory() as session:
                from sqlalchemy import text
                await session.execute(
                    text(f"SET LOCAL app.tenant_id = '{tenant_id}'")
                )

                state = StateManager(session)

                # 1 — Mark node completed, propagate edge data_refs
                info = await state.mark_node_completed(
                    node_id, output_ref, output_summary
                )
                dag_id = info["dag_id"]
                phase_number = info["phase_number"]

                # 2 — Store artifact
                tool = event.get("tool", "unknown")
                await state.store_artifact(
                    scan_id=scan_id, node_id=node_id, tenant_id=tenant_id,
                    artifact_type=tool, storage_ref=output_ref,
                )

                # 3 — Update scan progress
                progress = await state.update_scan_progress(scan_id)

                # 4 — Evaluate phase and advance
                controller = PhaseController(session)
                dag_status, ready_nodes = await controller.evaluate_and_advance(
                    dag_id, phase_number
                )

                # 5 — Dispatch new ready nodes
                if ready_nodes:
                    target = event.get("target", "")
                    dispatcher = JobDispatcher(session, self._redis)
                    await dispatcher.dispatch_nodes(
                        ready_nodes,
                        scan_id=scan_id, tenant_id=tenant_id,
                        target=target,
                    )

                # 6 — Handle DAG completion
                if dag_status == "completed":
                    await state.transition_scan(scan_id, "completed")
                    await self._concurrency.decrement_tenant_scans(tenant_id)
                    logger.info("Scan %s COMPLETED (progress=%d%%)", scan_id, progress)
                elif dag_status == "failed":
                    await state.transition_scan(scan_id, "failed")
                    await self._concurrency.decrement_tenant_scans(tenant_id)
                else:
                    # Still running — ensure scan is in 'running' status
                    await state.transition_scan(scan_id, "running")

                await session.commit()

            await self._concurrency.mark_event_processed(event_id)

        except Exception:
            logger.exception("Failed to handle job.completed for scan %s", scan_id)
        finally:
            await self._concurrency.release_scan_lock(scan_id)

    # ── job.failed ───────────────────────────────────────────────

    async def handle_job_failed(self, event: dict[str, Any]) -> None:
        """Handle a job.failed event from a worker.

        1. Mark node as failed
        2. Check retry eligibility
        3. If retryable → reset node, wait backoff, dispatch
        4. If not → evaluate phase
        5. If phase failed → fail DAG and scan
        """
        event_id = event.get("event_id", "")
        scan_id = uuid.UUID(event["scan_id"])
        tenant_id = uuid.UUID(event["tenant_id"])
        node_id = uuid.UUID(event["node_id"]) if event.get("node_id") else None
        error_code = event.get("error_code", "UNKNOWN")
        error_message = event.get("error_message", "Unknown error")

        if await self._concurrency.is_event_processed(event_id):
            return

        if not node_id:
            return

        if not await self._concurrency.acquire_scan_lock(scan_id):
            return

        try:
            async with self._session_factory() as session:
                from sqlalchemy import text
                await session.execute(
                    text(f"SET LOCAL app.tenant_id = '{tenant_id}'")
                )

                state = StateManager(session)

                # 1 — Mark node failed
                info = await state.mark_node_failed(node_id, error_message)
                dag_id = info["dag_id"]
                phase_number = info["phase_number"]
                retry_count = info["retry_count"]
                max_retries = info["max_retries"]

                # 2 — Check retry
                if self._retry_mgr.should_retry(
                    retry_count=retry_count,
                    max_retries=max_retries,
                    error_code=error_code,
                ):
                    # Reset node for retry
                    await state.reset_node_for_retry(node_id)
                    await session.commit()

                    # Backoff
                    await self._retry_mgr.wait_for_backoff(retry_count)

                    # Re-dispatch
                    async with self._session_factory() as session2:
                        await session2.execute(
                            text(f"SET LOCAL app.tenant_id = '{tenant_id}'")
                        )
                        resolver = DependencyResolver(session2)
                        ready = await resolver.get_ready_nodes(dag_id)
                        if ready:
                            dispatcher = JobDispatcher(session2, self._redis)
                            await dispatcher.dispatch_nodes(
                                ready, scan_id=scan_id, tenant_id=tenant_id,
                                target=event.get("target", ""),
                            )
                        await session2.commit()

                    logger.info(
                        "Node %s retry #%d scheduled", node_id, retry_count + 1
                    )
                else:
                    # No retry — evaluate phase status
                    controller = PhaseController(session)
                    dag_status, ready_nodes = await controller.evaluate_and_advance(
                        dag_id, phase_number
                    )

                    if ready_nodes:
                        dispatcher = JobDispatcher(session, self._redis)
                        await dispatcher.dispatch_nodes(
                            ready_nodes, scan_id=scan_id, tenant_id=tenant_id,
                            target=event.get("target", ""),
                        )

                    if dag_status == "failed":
                        await state.transition_scan(scan_id, "failed")
                        await self._concurrency.decrement_tenant_scans(tenant_id)
                    elif dag_status == "completed":
                        await state.transition_scan(scan_id, "completed")
                        await self._concurrency.decrement_tenant_scans(tenant_id)

                    await session.commit()

            await self._concurrency.mark_event_processed(event_id)

        except Exception:
            logger.exception("Failed to handle job.failed for scan %s", scan_id)
        finally:
            await self._concurrency.release_scan_lock(scan_id)
