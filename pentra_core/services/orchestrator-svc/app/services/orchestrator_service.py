"""Orchestrator service — facade coordinating all engine components.

This is the central entry point for scan orchestration logic.
It receives events from ScanConsumer and JobEventHandler and
delegates pipeline execution to PipelineExecutor (MOD-04.5).

Event flow:
  scan.created → build DAG → PipelineExecutor.start_pipeline()
  scan.cancelled → set cancellation flag → stop future work dispatch
  job.completed → update state → PipelineExecutor.execute_after_completion()
  job.failed → retry / fail → PipelineExecutor.execute_after_failure()
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.engine.concurrency_controller import ConcurrencyController
from app.engine.dag_builder import DAGBuilder
from app.engine.dependency_resolver import DependencyResolver
from app.engine.job_dispatcher import JobDispatcher
from app.engine.pipeline_executor import PipelineExecutor
from app.engine.phase_controller import PhaseController
from app.engine.retry_manager import RetryManager
from app.engine.state_manager import StateManager
from app.engine.artifact_bus import ArtifactBus
from app.engine.historical_finding_archive import sync_completed_scan_historical_findings
from app.engine.scan_event_publisher import ScanEventPublisher

logger = logging.getLogger(__name__)

_JOB_EVENT_LOCK_RETRY_ATTEMPTS = 25
_JOB_EVENT_LOCK_RETRY_DELAY_SECONDS = 0.2


class OrchestratorService:
    """Facade orchestrating the scan execution pipeline.

    Usage::

        svc = OrchestratorService(session_factory, redis)
        await svc.handle_scan_event(event)         # from ScanConsumer
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
        self._events = ScanEventPublisher(redis)

    async def _decrement_active_scan_quota(
        self,
        session: AsyncSession,
        tenant_id: uuid.UUID,
    ) -> None:
        """Decrement the tenant's active scan count in the DB quota row."""
        from sqlalchemy import text

        await session.execute(
            text("""
                UPDATE tenant_quotas
                SET active_scans = GREATEST(active_scans - 1, 0),
                    updated_at = NOW()
                WHERE tenant_id = :tenant_id
            """),
            {"tenant_id": str(tenant_id)},
        )

    async def _sync_historical_findings_best_effort(
        self,
        session: AsyncSession,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> None:
        try:
            await sync_completed_scan_historical_findings(
                session,
                scan_id=scan_id,
                tenant_id=tenant_id,
            )
        except Exception:
            logger.exception(
                "Historical finding archive sync failed for completed scan %s",
                scan_id,
            )

    async def _publish_pending_dispatches_best_effort(
        self,
        *,
        tenant_id: uuid.UUID | None = None,
        limit: int = 100,
    ) -> int:
        """Flush committed job dispatch outbox entries without risking replay."""
        if limit <= 0:
            return 0

        try:
            async with self._session_factory() as session:
                from sqlalchemy import text

                if tenant_id is not None:
                    await session.execute(
                        text(f"SET LOCAL app.tenant_id = '{tenant_id}'")
                    )

                dispatcher = JobDispatcher(session, self._redis)
                published = await dispatcher.publish_pending_jobs_for_tenant(
                    limit=limit,
                    tenant_id=tenant_id,
                )
                await session.commit()
                return published
        except Exception:
            logger.exception("Failed to flush pending job dispatch outbox")
            return 0

    async def _acquire_scan_lock_with_retry(
        self,
        scan_id: uuid.UUID,
        *,
        holder: str = "orchestrator",
        attempts: int = 1,
        delay_seconds: float = 0.0,
    ) -> bool:
        for attempt in range(1, max(attempts, 1) + 1):
            if await self._concurrency.acquire_scan_lock(scan_id, holder=holder):
                return True
            if attempt < attempts and delay_seconds > 0:
                await asyncio.sleep(delay_seconds)
        return False

    # ── scan events ──────────────────────────────────────────────

    async def handle_scan_event(self, event: dict[str, Any]) -> None:
        """Dispatch durable scan events to the correct handler."""
        event_type = event.get("event_type", "")

        if event_type == "scan.created":
            await self.handle_scan_created(event)
            return

        if event_type == "scan.cancelled":
            await self.handle_scan_cancelled(event)
            return

        if event_type == "scan.resumed":
            await self.handle_scan_resumed(event)
            return

        logger.warning("Unknown scan event type received: %s", event_type)

    # ── scan.created ─────────────────────────────────────────────

    async def handle_scan_created(self, event: dict[str, Any]) -> None:
        """Handle a scan.created event from the API gateway.

        1. Dedup event (idempotency check)
        2. Acquire distributed lock
        3. Build DAG
        4. Start pipeline (activate phase 0, resolve, dispatch)
        5. Update scan status: queued → validating
        """
        event_id = event.get("event_id", "")
        scan_id = uuid.UUID(event["scan_id"])
        tenant_id = uuid.UUID(event["tenant_id"])
        scan_type = event["scan_type"]
        priority = event.get("priority", "normal")
        asset_type = event.get("asset_type", "web_app")
        target = event.get("target", "")
        config = event.get("config", {})

        # Idempotency
        if await self._concurrency.is_event_processed(event_id):
            logger.info("Event %s already processed — skipping", event_id)
            return

        # Distributed lock
        if not await self._acquire_scan_lock_with_retry(scan_id):
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

                # 2 — Start pipeline (activate first phase → resolve → dispatch)
                executor = PipelineExecutor(session, self._redis, self._events)
                result = await executor.start_pipeline(
                    dag_id=dag_id,
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    target=target,
                    priority=priority,
                )

                # 3 — Transition scan status
                state = StateManager(session)

                await state.transition_scan(scan_id, "validating")

                await session.commit()

            await self._publish_pending_dispatches_best_effort(
                tenant_id=tenant_id,
                limit=max(len(result.get("dispatched_job_ids", [])), 1),
            )

            # Mark event as processed
            await self._concurrency.mark_event_processed(event_id)

            logger.info(
                "Scan orchestration started: scan=%s dag=%s type=%s dispatched=%d",
                scan_id, dag_id, scan_type, result["dispatched_count"],
            )

        except Exception:
            logger.exception("Failed to handle scan.created for %s", scan_id)
            raise
        finally:
            await self._concurrency.release_scan_lock(scan_id)

    async def handle_scan_cancelled(self, event: dict[str, Any]) -> None:
        """Handle a durable scan.cancelled event from the API gateway."""
        event_id = event.get("event_id", "")
        scan_id = uuid.UUID(event["scan_id"])
        old_status = event.get("old_status", "running")

        if event_id and await self._concurrency.is_event_processed(event_id):
            logger.info("Cancellation event %s already processed — skipping", event_id)
            return

        try:
            await self.set_scan_cancelled(scan_id, old_status=old_status)
            if event_id:
                await self._concurrency.mark_event_processed(event_id)
            logger.info("Cancellation propagated for scan %s", scan_id)
        except Exception:
            logger.exception("Failed to handle scan.cancelled for %s", scan_id)
            raise

    async def handle_scan_resumed(self, event: dict[str, Any]) -> None:
        """Handle a durable scan.resumed event from the API gateway."""
        event_id = event.get("event_id", "")
        scan_id = uuid.UUID(event["scan_id"])
        tenant_id = uuid.UUID(event["tenant_id"])

        if event_id and await self._concurrency.is_event_processed(event_id):
            logger.info("Resume event %s already processed — skipping", event_id)
            return

        if not await self._acquire_scan_lock_with_retry(scan_id):
            raise RuntimeError(f"Cannot acquire lock for resumed scan {scan_id}")

        try:
            dispatch_count = 0
            async with self._session_factory() as session:
                from sqlalchemy import text
                await session.execute(
                    text(f"SET LOCAL app.tenant_id = '{tenant_id}'")
                )

                dag_result = await session.execute(
                    text("SELECT id FROM scan_dags WHERE scan_id = :scan_id"),
                    {"scan_id": str(scan_id)},
                )
                dag_id = dag_result.scalar_one_or_none()
                if dag_id is None:
                    logger.info(
                        "Resume event for scan %s has no DAG yet — ignoring",
                        scan_id,
                    )
                    await session.commit()
                else:
                    scan_result = await session.execute(
                        text("""
                            SELECT target, priority
                            FROM scans s
                            JOIN assets a ON a.id = s.asset_id
                            WHERE s.id = :scan_id
                        """),
                        {"scan_id": str(scan_id)},
                    )
                    scan_row = scan_result.mappings().first()
                    executor = PipelineExecutor(session, self._redis, self._events)
                    result = await executor.resume_pipeline(
                        dag_id=uuid.UUID(str(dag_id)),
                        scan_id=scan_id,
                        tenant_id=tenant_id,
                        target=str(scan_row["target"]) if scan_row else "",
                        priority=str(scan_row["priority"]) if scan_row else "normal",
                    )
                    dispatch_count = len(result.get("dispatched_job_ids", []))
                    await session.commit()

            if dispatch_count > 0:
                await self._publish_pending_dispatches_best_effort(
                    tenant_id=tenant_id,
                    limit=dispatch_count,
                )
            if event_id:
                await self._concurrency.mark_event_processed(event_id)
            logger.info("Resume propagated for scan %s", scan_id)
        except Exception:
            logger.exception("Failed to handle scan.resumed for %s", scan_id)
            raise
        finally:
            await self._concurrency.release_scan_lock(scan_id)

    # ── job.completed ────────────────────────────────────────────

    async def handle_job_completed(self, event: dict[str, Any]) -> None:
        """Handle a job.completed event from a worker.

        1. Mark node as completed + propagate edge data_refs
        2. Delegate to PipelineExecutor for resolve → dispatch → advance
        3. Handle DAG completion
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

        # Guard: skip events for cancelled scans
        if await self._is_scan_cancelled(scan_id):
            logger.info("Ignoring job.completed for cancelled scan %s", scan_id)
            await self._concurrency.mark_event_processed(event_id)
            return

        if not await self._acquire_scan_lock_with_retry(
            scan_id,
            attempts=_JOB_EVENT_LOCK_RETRY_ATTEMPTS,
            delay_seconds=_JOB_EVENT_LOCK_RETRY_DELAY_SECONDS,
        ):
            raise RuntimeError(f"Cannot acquire lock for scan {scan_id}")

        try:
            async with self._session_factory() as session:
                from sqlalchemy import text
                await session.execute(
                    text(f"SET LOCAL app.tenant_id = '{tenant_id}'")
                )

                state = StateManager(session)
                scan_status = await self._load_scan_status(session, scan_id)
                scan_is_paused = scan_status == "paused"

                # 0 — Ensure scan is in 'running' state
                # (handles validating → running on first event)
                if not scan_is_paused:
                    await state.transition_scan(scan_id, "running")

                # 1 — Mark node completed, propagate edge data_refs
                info = await state.mark_node_completed(
                    node_id, output_ref, output_summary
                )
                if not info.get("state_changed", True):
                    await session.commit()
                    await self._concurrency.mark_event_processed(event_id)
                    logger.info(
                        "Ignoring job.completed for node %s already in status %s",
                        node_id,
                        info.get("current_status"),
                    )
                    return
                dag_id = info["dag_id"]
                phase_number = info["phase_number"]

                # 2 — Delegate to pipeline executor
                executor = PipelineExecutor(session, self._redis, self._events)
                result = await executor.execute_after_completion(
                    dag_id=dag_id,
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    node_id=node_id,
                    phase_number=phase_number,
                    output_ref=output_ref,
                    output_summary=output_summary,
                    tool=event.get("tool", "unknown"),
                    target=event.get("target", ""),
                    priority=event.get("priority", "normal"),
                    allow_dispatch=not scan_is_paused,
                )

                # 3 — MOD-06: Artifact bus — trigger exploit planning
                tool = event.get("tool", "unknown")
                artifact_type = output_summary.get("artifact_type", tool)
                bus = ArtifactBus(session)
                bus_result = await bus.process_completed_node(
                    dag_id=dag_id,
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    node_id=node_id,
                    tool=tool,
                    artifact_type=artifact_type,
                    output_ref=output_ref,
                    output_summary=output_summary,
                )

                # If exploit planner, strategy, or exploration created dynamic nodes, re-resolve
                dynamic_job_ids: list[uuid.UUID] = []
                new_dynamic = (
                    bus_result["dynamic_nodes_created"]
                    + bus_result.get("strategy_nodes_created", 0)
                    + bus_result.get("exploration_nodes_created", 0)
                )
                if new_dynamic > 0:
                    newly_ready = await executor._resolver.resolve_ready_nodes(dag_id)
                    if newly_ready:
                        scan_config = await executor._load_scan_config(scan_id)
                        dynamic_job_ids = await executor._dispatcher.dispatch_nodes(
                            newly_ready,
                            scan_id=scan_id,
                            tenant_id=tenant_id,
                            target=event.get("target", ""),
                            priority=event.get("priority", "normal"),
                            config=scan_config,
                        )

                # 4 — Handle DAG completion + publish real-time events
                dag_status = result["dag_status"]
                tool = event.get("tool", "unknown")
                await self._events.publish_node_update(
                    scan_id, node_id, tool, "completed", output_summary,
                )
                if hasattr(self._events, "publish_job_update"):
                    await self._events.publish_job_update(
                        scan_id,
                        job_id=uuid.UUID(str(event["job_id"])) if event.get("job_id") else None,
                        node_id=node_id,
                        tool=tool,
                        status="completed",
                        phase_number=phase_number,
                        execution_provenance=str((output_summary or {}).get("execution_provenance") or "") or None,
                        execution_reason=str((output_summary or {}).get("execution_reason") or "") or None,
                        execution_class=str((output_summary or {}).get("execution_class") or "") or None,
                        policy_state=str((output_summary or {}).get("policy_state") or "") or None,
                        runtime_stage=(
                            str(execution_log.get("runtime_stage") or "").strip() or "completed"
                        ),
                        last_chunk_at=str(execution_log.get("last_chunk_at") or "").strip() or None,
                        stream_complete=bool(execution_log.get("stream_complete", True)),
                        artifact_ref=str(event.get("output_ref") or "") or None,
                        duration_ms=int((output_summary or {}).get("duration_ms") or 0) or None,
                    )
                execution_log = (
                    (output_summary or {}).get("execution_log")
                    if isinstance((output_summary or {}).get("execution_log"), dict)
                    else {}
                ) or {}
                canonical_command = (
                    execution_log.get("canonical_command")
                    if isinstance(execution_log.get("canonical_command"), dict)
                    else {}
                ) or {}
                if hasattr(self._events, "publish_command_update"):
                    await self._events.publish_command_update(
                        scan_id,
                        job_id=uuid.UUID(str(event["job_id"])) if event.get("job_id") else None,
                        node_id=node_id,
                        tool=tool,
                        status="completed",
                        phase_number=phase_number,
                        execution_provenance=str((output_summary or {}).get("execution_provenance") or "") or None,
                        execution_reason=str((output_summary or {}).get("execution_reason") or "") or None,
                        execution_class=str((output_summary or {}).get("execution_class") or "") or None,
                        policy_state=str((output_summary or {}).get("policy_state") or "") or None,
                        runtime_stage=(
                            str(execution_log.get("runtime_stage") or "").strip() or "completed"
                        ),
                        last_chunk_at=str(execution_log.get("last_chunk_at") or "").strip() or None,
                        stream_complete=bool(execution_log.get("stream_complete", True)),
                        command=list(execution_log.get("command") or []),
                        display_command=str(
                            execution_log.get("display_command")
                            or canonical_command.get("display_command")
                            or ""
                        )
                        or None,
                        tool_binary=str(canonical_command.get("tool_binary") or "").strip() or None,
                        container_image=str(canonical_command.get("container_image") or "").strip() or None,
                        entrypoint=list(canonical_command.get("entrypoint") or []),
                        working_dir=str(canonical_command.get("working_dir") or "").strip() or None,
                        channel="command",
                        chunk_text=str(
                            execution_log.get("display_command")
                            or canonical_command.get("display_command")
                            or " ".join(list(execution_log.get("command") or []))
                        ).strip()
                        or None,
                        chunk_seq=0,
                        stdout_preview=str(execution_log.get("stdout_preview") or "") or None,
                        stderr_preview=str(execution_log.get("stderr_preview") or "") or None,
                        exit_code=execution_log.get("exit_code"),
                        duration_ms=int((output_summary or {}).get("duration_ms") or 0) or None,
                        artifact_ref=str(execution_log.get("command_artifact_ref") or event.get("output_ref") or "") or None,
                        full_stdout_artifact_ref=(
                            str(execution_log.get("full_stdout_artifact_ref") or "").strip() or None
                        ),
                        full_stderr_artifact_ref=(
                            str(execution_log.get("full_stderr_artifact_ref") or "").strip() or None
                        ),
                        command_artifact_ref=(
                            str(execution_log.get("command_artifact_ref") or "").strip() or None
                        ),
                        session_artifact_ref=(
                            str(execution_log.get("session_artifact_ref") or "").strip() or None
                        ),
                    )
                await self._events.publish_progress(
                    scan_id, result["progress"],
                )
                if dag_status == "completed":
                    await state.transition_scan(scan_id, "completed")
                    await self._events.publish_progress(scan_id, 100)
                    await self._sync_historical_findings_best_effort(
                        session,
                        scan_id=scan_id,
                        tenant_id=tenant_id,
                    )
                    await self._decrement_active_scan_quota(session, tenant_id)
                    await self._events.publish_status_change(
                        scan_id,
                        "paused" if scan_is_paused else "running",
                        "completed",
                    )
                    logger.info(
                        "Scan %s COMPLETED (progress=%d%%)",
                        scan_id, result["progress"],
                    )
                elif dag_status == "failed":
                    await state.transition_scan(scan_id, "failed")
                    await self._decrement_active_scan_quota(session, tenant_id)
                    await self._events.publish_status_change(
                        scan_id,
                        "paused" if scan_is_paused else "running",
                        "failed",
                    )
                else:
                    pass  # already transitioned to 'running' above

                await session.commit()

            dispatch_count = len(result.get("dispatched_job_ids", [])) + len(dynamic_job_ids)
            await self._publish_pending_dispatches_best_effort(
                tenant_id=tenant_id,
                limit=max(dispatch_count, 1),
            )

            # Only write dedup state after the DB commit succeeds.
            try:
                await self._redis.set(
                    f"pentra:node_completed:{node_id}", "1", ex=86400,
                )
            except Exception:
                logger.debug("Failed to set node_completed cache for %s", node_id)

            await self._concurrency.mark_event_processed(event_id)

        except Exception:
            logger.exception("Failed to handle job.completed for scan %s", scan_id)
            raise  # Re-raise so the event handler does NOT ACK — allows retry
        finally:
            await self._concurrency.release_scan_lock(scan_id)

    # ── job.failed ───────────────────────────────────────────────

    async def handle_job_failed(self, event: dict[str, Any]) -> None:
        """Handle a job.failed event from a worker.

        1. Mark node as failed
        2. Check retry eligibility
        3. If retryable → reset node, wait backoff, re-dispatch
        4. If not → propagate failure + evaluate phase via PipelineExecutor
        5. Handle DAG failure
        """
        event_id = event.get("event_id", "")
        scan_id = uuid.UUID(event["scan_id"])
        tenant_id = uuid.UUID(event["tenant_id"])
        node_id = uuid.UUID(event["node_id"]) if event.get("node_id") else None
        error_code = event.get("error_code", "UNKNOWN")
        error_message = event.get("error_message", "Unknown error")
        output_summary = event.get("output_summary", {})
        if not isinstance(output_summary, dict):
            output_summary = {}
        output_ref = str(event.get("output_ref") or "").strip() or None

        if await self._concurrency.is_event_processed(event_id):
            return

        if not node_id:
            return

        # Guard: skip events for cancelled scans
        if await self._is_scan_cancelled(scan_id):
            logger.info("Ignoring job.failed for cancelled scan %s", scan_id)
            await self._concurrency.mark_event_processed(event_id)
            return

        if not await self._acquire_scan_lock_with_retry(
            scan_id,
            attempts=_JOB_EVENT_LOCK_RETRY_ATTEMPTS,
            delay_seconds=_JOB_EVENT_LOCK_RETRY_DELAY_SECONDS,
        ):
            raise RuntimeError(f"Cannot acquire lock for scan {scan_id}")

        lock_released = False
        post_commit_dispatch_count = 0
        try:
            async with self._session_factory() as session:
                from sqlalchemy import text
                await session.execute(
                    text(f"SET LOCAL app.tenant_id = '{tenant_id}'")
                )

                state = StateManager(session)
                scan_status = await self._load_scan_status(session, scan_id)
                scan_is_paused = scan_status == "paused"

                # 0 — Ensure scan is in 'running' state
                if not scan_is_paused:
                    await state.transition_scan(scan_id, "running")

                # 1 — Mark node failed
                info = await state.mark_node_failed(
                    node_id,
                    error_message,
                    output_ref=output_ref,
                    output_summary=output_summary or None,
                )
                if not info.get("state_changed", True):
                    await session.commit()
                    await self._concurrency.mark_event_processed(event_id)
                    logger.info(
                        "Ignoring job.failed for node %s already in status %s",
                        node_id,
                        info.get("current_status"),
                    )
                    return
                dag_id = info["dag_id"]
                phase_number = info["phase_number"]
                retry_count = info["retry_count"]
                max_retries = info["max_retries"]

                # 2 — Check retry
                if self._retry_mgr.should_retry(
                    retry_count=retry_count,
                    max_retries=max_retries,
                    error_code=error_code,
                    tool_name=str(event.get("tool") or ""),
                ):
                    # Reset node for retry (failed → pending)
                    await state.reset_node_for_retry(node_id)
                    if scan_is_paused:
                        await session.commit()
                        await self._concurrency.mark_event_processed(event_id)
                        logger.info(
                            "Deferred retry for paused scan %s node %s",
                            scan_id,
                            node_id,
                        )
                        return
                    await session.commit()

                    # Release lock BEFORE backoff to avoid holding it during sleep
                    await self._concurrency.release_scan_lock(scan_id)
                    lock_released = True

                    # Backoff (can be up to 120s — don't hold the lock!)
                    await self._retry_mgr.wait_for_backoff(retry_count)

                    # Re-acquire lock for dispatch
                    if not await self._acquire_scan_lock_with_retry(
                        scan_id,
                        attempts=_JOB_EVENT_LOCK_RETRY_ATTEMPTS,
                        delay_seconds=_JOB_EVENT_LOCK_RETRY_DELAY_SECONDS,
                    ):
                        logger.error("Cannot re-acquire lock for retry dispatch on scan %s", scan_id)
                    else:
                        try:
                            # Re-resolve and dispatch in fresh session
                            async with self._session_factory() as session2:
                                await session2.execute(
                                    text(f"SET LOCAL app.tenant_id = '{tenant_id}'")
                                )
                                resolver = DependencyResolver(session2)
                                ready = await resolver.resolve_ready_nodes(dag_id)
                                if ready:
                                    dispatcher = JobDispatcher(session2, self._redis)
                                    config_result = await session2.execute(
                                        text("SELECT config FROM scans WHERE id = :id"),
                                        {"id": str(scan_id)},
                                    )
                                    scan_config = config_result.scalar_one_or_none()
                                    ready_job_ids = await dispatcher.dispatch_nodes(
                                        ready, scan_id=scan_id, tenant_id=tenant_id,
                                        target=event.get("target", ""),
                                        priority=event.get("priority", "normal"),
                                        config=scan_config if isinstance(scan_config, dict) else {},
                                    )
                                else:
                                    ready_job_ids = []
                                await session2.commit()
                            await self._publish_pending_dispatches_best_effort(
                                tenant_id=tenant_id,
                                limit=max(len(ready_job_ids), 1),
                            )
                        finally:
                            await self._concurrency.release_scan_lock(scan_id)

                    logger.info(
                        "Node %s retry #%d scheduled", node_id, retry_count + 1
                    )
                else:
                    # No retry — permanent failure
                    # Delegate to pipeline executor (propagates failure + evaluates)
                    executor = PipelineExecutor(session, self._redis, self._events)
                    result = await executor.execute_after_failure(
                        dag_id=dag_id,
                        scan_id=scan_id,
                        tenant_id=tenant_id,
                        node_id=node_id,
                        phase_number=phase_number,
                        target=event.get("target", ""),
                        priority=event.get("priority", "normal"),
                        allow_dispatch=not scan_is_paused,
                    )

                    tool = str(event.get("tool") or "unknown")
                    execution_log = (
                        output_summary.get("execution_log")
                        if isinstance(output_summary.get("execution_log"), dict)
                        else {}
                    ) or {}

                    await self._events.publish_node_update(
                        scan_id,
                        node_id,
                        tool,
                        "failed",
                        output_summary,
                    )

                    if hasattr(self._events, "publish_job_update"):
                        await self._events.publish_job_update(
                            scan_id,
                            job_id=uuid.UUID(str(event["job_id"])) if event.get("job_id") else None,
                            node_id=node_id,
                            tool=tool,
                            status="failed",
                            phase_number=phase_number,
                            execution_provenance=(
                                str(output_summary.get("execution_provenance") or "").strip()
                                or ("blocked" if error_code == "TARGET_POLICY_BLOCKED" else None)
                            ),
                            execution_reason=(
                                str(output_summary.get("execution_reason") or "").strip()
                                or error_code
                                or error_message
                            ),
                            execution_class=(
                                str(output_summary.get("execution_class") or "").strip() or None
                            ),
                            policy_state=str(output_summary.get("policy_state") or "").strip() or None,
                            runtime_stage=(
                                str(execution_log.get("runtime_stage") or "").strip() or "failed"
                            ),
                            last_chunk_at=str(execution_log.get("last_chunk_at") or "").strip() or None,
                            stream_complete=bool(execution_log.get("stream_complete", True)),
                            artifact_ref=output_ref,
                            duration_ms=int(output_summary.get("duration_ms") or 0) or None,
                        )
                    if hasattr(self._events, "publish_command_update"):
                        canonical_command = (
                            execution_log.get("canonical_command")
                            if isinstance(execution_log.get("canonical_command"), dict)
                            else {}
                        ) or {}
                        await self._events.publish_command_update(
                            scan_id,
                            job_id=uuid.UUID(str(event["job_id"])) if event.get("job_id") else None,
                            node_id=node_id,
                            tool=tool,
                            status="failed",
                            phase_number=phase_number,
                            execution_provenance=(
                                str(output_summary.get("execution_provenance") or "").strip() or None
                            ),
                            execution_reason=(
                                str(output_summary.get("execution_reason") or "").strip()
                                or error_code
                                or error_message
                            ),
                            execution_class=(
                                str(output_summary.get("execution_class") or "").strip() or None
                            ),
                            policy_state=str(output_summary.get("policy_state") or "").strip() or None,
                            runtime_stage=(
                                str(execution_log.get("runtime_stage") or "").strip() or "failed"
                            ),
                            last_chunk_at=str(execution_log.get("last_chunk_at") or "").strip() or None,
                            stream_complete=bool(execution_log.get("stream_complete", True)),
                            command=list(execution_log.get("command") or []),
                            display_command=str(
                                execution_log.get("display_command")
                                or canonical_command.get("display_command")
                                or ""
                            )
                            or None,
                            tool_binary=str(canonical_command.get("tool_binary") or "").strip() or None,
                            container_image=str(canonical_command.get("container_image") or "").strip() or None,
                            entrypoint=list(canonical_command.get("entrypoint") or []),
                            working_dir=str(canonical_command.get("working_dir") or "").strip() or None,
                            channel="command",
                            chunk_text=str(
                                execution_log.get("display_command")
                                or canonical_command.get("display_command")
                                or " ".join(list(execution_log.get("command") or []))
                            ).strip()
                            or None,
                            chunk_seq=0,
                            stdout_preview=str(execution_log.get("stdout_preview") or "") or None,
                            stderr_preview=str(execution_log.get("stderr_preview") or "") or None,
                            exit_code=execution_log.get("exit_code"),
                            duration_ms=int(output_summary.get("duration_ms") or 0) or None,
                            artifact_ref=(
                                str(execution_log.get("command_artifact_ref") or output_ref or "").strip()
                                or None
                            ),
                            full_stdout_artifact_ref=(
                                str(execution_log.get("full_stdout_artifact_ref") or "").strip() or None
                            ),
                            full_stderr_artifact_ref=(
                                str(execution_log.get("full_stderr_artifact_ref") or "").strip() or None
                            ),
                            command_artifact_ref=(
                                str(execution_log.get("command_artifact_ref") or "").strip() or None
                            ),
                            session_artifact_ref=(
                                str(execution_log.get("session_artifact_ref") or "").strip() or None
                            ),
                        )

                    dag_status = result["dag_status"]
                    if dag_status == "failed":
                        await state.transition_scan(scan_id, "failed")
                        await self._decrement_active_scan_quota(session, tenant_id)
                        await self._events.publish_status_change(
                            scan_id,
                            "paused" if scan_is_paused else "running",
                            "failed",
                        )
                    elif dag_status == "completed":
                        await state.transition_scan(scan_id, "completed")
                        await self._events.publish_progress(scan_id, 100)
                        await self._sync_historical_findings_best_effort(
                            session,
                            scan_id=scan_id,
                            tenant_id=tenant_id,
                        )
                        await self._decrement_active_scan_quota(session, tenant_id)
                        await self._events.publish_status_change(
                            scan_id,
                            "paused" if scan_is_paused else "running",
                            "completed",
                        )

                    # Update progress after failure propagation
                    await state.update_scan_progress(scan_id)

                    post_commit_dispatch_count = len(result.get("dispatched_job_ids", []))
                    await session.commit()

            if post_commit_dispatch_count > 0:
                await self._publish_pending_dispatches_best_effort(
                    tenant_id=tenant_id,
                    limit=post_commit_dispatch_count,
                )

            await self._concurrency.mark_event_processed(event_id)

        except Exception:
            logger.exception("Failed to handle job.failed for scan %s", scan_id)
            raise  # Re-raise so the event handler does NOT ACK — allows retry
        finally:
            if not lock_released:
                await self._concurrency.release_scan_lock(scan_id)

    # ── Cancellation helpers ─────────────────────────────────────

    _SCAN_CANCEL_PREFIX = "pentra:scan:cancelled"

    async def _is_scan_cancelled(self, scan_id: uuid.UUID) -> bool:
        """Check if a scan has been cancelled via Redis flag."""
        try:
            result = await self._redis.get(
                f"{self._SCAN_CANCEL_PREFIX}:{scan_id}"
            )
            return result is not None
        except Exception:
            return False

    async def _load_scan_status(
        self,
        session: AsyncSession,
        scan_id: uuid.UUID,
    ) -> str | None:
        from sqlalchemy import text

        result = await session.execute(
            text(f"SELECT status FROM scans WHERE id = '{scan_id}'")
        )
        if hasattr(result, "scalar_one_or_none"):
            value = result.scalar_one_or_none()
            if isinstance(value, str):
                return value
        if hasattr(result, "mappings"):
            mappings = result.mappings()
            if hasattr(mappings, "first"):
                row = mappings.first()
            elif hasattr(mappings, "all"):
                rows = mappings.all()
                row = rows[0] if rows else None
            else:
                row = None
            if isinstance(row, dict) and row.get("status") is not None:
                return str(row["status"])
        return "running"

    async def set_scan_cancelled(
        self,
        scan_id: uuid.UUID,
        *,
        old_status: str = "running",
    ) -> None:
        """Set the cancellation flag for a scan in Redis.

        Called after the API gateway emits a durable ``scan.cancelled`` event.
        Workers and the orchestrator check this flag to skip work.
        """
        try:
            # Set flag with 24h TTL (scans shouldn't run longer)
            await self._redis.set(
                f"{self._SCAN_CANCEL_PREFIX}:{scan_id}", "1", ex=86400,
            )
            # Publish cancel event via Pub/Sub for real-time WS notification
            await self._events.publish_status_change(
                scan_id, old_status, "cancelled",
            )
            logger.info("Scan %s marked as cancelled", scan_id)
        except Exception:
            logger.exception("Failed to set cancel flag for scan %s", scan_id)
