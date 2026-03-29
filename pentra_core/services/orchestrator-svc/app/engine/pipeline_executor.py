"""Pipeline executor — central DAG pipeline execution coordinator.

MOD-04.5: Encapsulates the core execution loop:

  resolve_ready_nodes() → dispatch_nodes() → update_progress()

Called by OrchestratorService after events (node completion, node failure).
Coordinates: dependency resolution, phase transitions, failure propagation,
job dispatch, and progress tracking.

This replaces inline orchestration logic with a clean, composable coordinator.
"""

from __future__ import annotations

__classification__ = "runtime_hot_path"

import logging
import os
import uuid
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.engine.dependency_resolver import DependencyResolver, ReadyNode
from app.engine.job_dispatcher import JobDispatcher
from app.engine.phase_controller import PhaseController
from app.engine.state_manager import StateManager
from app.engine.ai_strategy_advisor import AIStrategyAdvisor, StrategyRecommendation
from app.engine.ai_strategy_followup_planner import AIStrategyFollowupPlanner
from app.engine.capability_advisory_service import CapabilityAdvisoryService
from app.engine.plan_mutator import PlanMutator
from app.engine.planner_target_model_loader import PlannerTargetModelLoader
from app.engine.strategic_planner import StrategicPlanner, StrategicPlannerContext
from app.engine.tactical_planner import TacticalPlanner

logger = logging.getLogger(__name__)


def _autonomy_disabled() -> bool:
    value = os.getenv("PENTRA_DISABLE_AUTONOMY", "false").strip().lower()
    return value in {"1", "true", "yes", "on"}


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
        event_publisher: Any | None = None,
    ) -> None:
        self._session = session
        self._redis = redis
        self._events = event_publisher
        self._state = StateManager(session)
        self._resolver = DependencyResolver(session)
        self._controller = PhaseController(session)
        self._dispatcher = JobDispatcher(session, redis)
        self._advisor = AIStrategyAdvisor()
        self._capability_advisor = CapabilityAdvisoryService()
        self._strategy_followups = AIStrategyFollowupPlanner(session)
        self._target_model_loader = PlannerTargetModelLoader(session)
        self._strategic_planner = StrategicPlanner()
        self._tactical_planner = TacticalPlanner(self._strategy_followups)
        self._plan_mutator = PlanMutator(
            session=session,
            followup_planner=self._strategy_followups,
            resolver=self._resolver,
            dispatcher=self._dispatcher,
        )

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
        allow_dispatch: bool = True,
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
            artifact_type=(output_summary or {}).get("artifact_type", tool),
            storage_ref=output_ref,
            content_type=(output_summary or {}).get("content_type", "application/json"),
            size_bytes=int((output_summary or {}).get("size_bytes", 0) or 0),
            checksum=(output_summary or {}).get("checksum"),
            metadata={
                "tool": tool,
                "item_count": int((output_summary or {}).get("item_count", 0) or 0),
                "finding_count": int((output_summary or {}).get("finding_count", 0) or 0),
                "evidence_count": int((output_summary or {}).get("evidence_count", 0) or 0),
                "severity_counts": (output_summary or {}).get("severity_counts", {}),
                "summary": (output_summary or {}).get("summary", {}),
                "items": (output_summary or {}).get("preview_items", []),
                "findings": (output_summary or {}).get("preview_findings", []),
                "duration_ms": int((output_summary or {}).get("duration_ms", 0) or 0),
                "execution_mode": (output_summary or {}).get("execution_mode"),
                "execution_provenance": (output_summary or {}).get("execution_provenance"),
                "execution_reason": (output_summary or {}).get("execution_reason"),
            },
        )

        # 2 — Resolve newly ready nodes (pending → ready)
        newly_ready = await self._resolver.resolve_ready_nodes(dag_id)

        # 3 — Evaluate phase and advance
        dag_status, phase_ready, phase_transitioned = await self._controller.evaluate_and_advance(
            dag_id, phase_number
        )

        # Combine ready nodes from resolution + phase advancement
        all_ready = newly_ready + phase_ready

        # 4 — AI planner runs at phase boundaries before static dispatch
        strategy_result = None
        planner_result = None
        ready_nodes_before_planner: list[ReadyNode] = []
        ready_nodes_after_planner: list[ReadyNode] = []
        if allow_dispatch and dag_status == "executing" and phase_transitioned:
            ready_nodes_before_planner = list(all_ready)
            strategy_result = await self._run_ai_strategy_advisor(
                scan_id=scan_id, dag_id=dag_id, tenant_id=tenant_id,
                phase_completed=phase_number,
            )
            if strategy_result is not None:
                planner_result = await self._apply_ai_planner(
                    dag_id=dag_id,
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    phase_completed=phase_number,
                    recommendation=strategy_result,
                    active_phase_tool_ids=[node.tool for node in ready_nodes_before_planner],
                    target=target,
                    priority=priority,
                )
                suppressed_node_ids = {
                    uuid.UUID(str(item))
                    for item in planner_result.get("suppressed_node_ids", [])
                }
                suppressed_tools = {
                    str(item)
                    for item in planner_result.get("suppressed_tool_ids", [])
                }
                all_ready = [
                    node
                    for node in all_ready
                    if node.node_id not in suppressed_node_ids and node.tool not in suppressed_tools
                ]
                ready_nodes_after_planner = list(all_ready)

        # 5 — Dispatch all remaining ready nodes
        dispatched: list[uuid.UUID] = []
        static_dispatched_nodes: list[ReadyNode] = []
        if allow_dispatch and all_ready:
            scan_config = await self._load_scan_config(scan_id)
            static_dispatched_nodes = list(all_ready)
            dispatched = await self._dispatcher.dispatch_nodes(
                all_ready,
                scan_id=scan_id,
                tenant_id=tenant_id,
                target=target,
                priority=priority,
                config=scan_config,
            )
        if planner_result is not None:
            dispatched.extend(planner_result.get("job_ids", []))
            if strategy_result is not None:
                await self._store_planner_effect_artifact(
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    phase_completed=phase_number,
                    recommendation=strategy_result,
                    planner_result=planner_result,
                    ready_nodes_before_planner=ready_nodes_before_planner,
                    ready_nodes_after_planner=ready_nodes_after_planner,
                    static_dispatched_nodes=static_dispatched_nodes,
                )

        # 6 — Update scan progress
        progress = await self._state.update_scan_progress(scan_id)

        logger.info(
            "Pipeline after completion: dag=%s status=%s dispatched=%d progress=%d%%",
            dag_id, dag_status, len(dispatched), progress,
        )

        result = {
            "dag_status": dag_status,
            "dispatched_count": len(dispatched),
            "dispatched_job_ids": dispatched,
            "progress": progress,
        }
        if strategy_result:
            result["ai_strategy"] = {
                "phase_decision": strategy_result.phase_decision,
                "recommended_tools": len(strategy_result.recommended_tools),
                "attack_vectors": strategy_result.attack_vectors,
            }
            if planner_result is not None:
                result["ai_strategy"].update(
                    {
                        "planner_decision": planner_result.get("planner_decision"),
                        "planner_mutation_kind": planner_result.get("mutation_kind"),
                        "planner_status": planner_result.get("status"),
                        "followup_nodes_created": len(
                            planner_result.get("created_node_ids", [])
                        ),
                        "followup_job_ids": planner_result.get("job_ids", []),
                        "planner_actions": planner_result.get("planner_actions", []),
                        "suppressed_tool_ids": planner_result.get("suppressed_tool_ids", []),
                        "suppressed_node_ids": planner_result.get("suppressed_node_ids", []),
                        "planner_dispatched_tools": planner_result.get(
                            "dispatched_tools", []
                        ),
                    }
                )
        return result

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
        allow_dispatch: bool = True,
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
        dag_status, phase_ready, _phase_transitioned = await self._controller.evaluate_and_advance(
            dag_id, phase_number
        )

        all_ready = ready + phase_ready

        # 4 — Dispatch ready nodes
        dispatched = []
        if allow_dispatch and all_ready:
            scan_config = await self._load_scan_config(scan_id)
            dispatched = await self._dispatcher.dispatch_nodes(
                all_ready,
                scan_id=scan_id,
                tenant_id=tenant_id,
                target=target,
                priority=priority,
                config=scan_config,
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
            "dispatched_job_ids": dispatched,
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
            scan_config = await self._load_scan_config(scan_id)
            dispatched = await self._dispatcher.dispatch_nodes(
                all_ready,
                scan_id=scan_id,
                tenant_id=tenant_id,
                target=target,
                priority=priority,
                config=scan_config,
            )

        logger.info(
            "Pipeline started: dag=%s dispatched=%d nodes",
            dag_id, len(dispatched),
        )

        return {
            "dispatched_count": len(dispatched),
            "dispatched_job_ids": dispatched,
        }

    async def resume_pipeline(
        self,
        *,
        dag_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        target: str = "",
        priority: str = "normal",
    ) -> dict[str, Any]:
        """Resume a paused pipeline by dispatching any ready work."""
        resolved_ready = await self._resolver.resolve_ready_nodes(dag_id)
        existing_ready = await self._resolver.get_ready_nodes(dag_id)
        ready_by_id: dict[uuid.UUID, ReadyNode] = {
            node.node_id: node for node in resolved_ready
        }
        for node in existing_ready:
            ready_by_id.setdefault(node.node_id, node)

        dispatched: list[uuid.UUID] = []
        if ready_by_id:
            scan_config = await self._load_scan_config(scan_id)
            dispatched = await self._dispatcher.dispatch_nodes(
                list(ready_by_id.values()),
                scan_id=scan_id,
                tenant_id=tenant_id,
                target=target,
                priority=priority,
                config=scan_config,
            )

        progress = await self._state.update_scan_progress(scan_id)
        logger.info(
            "Pipeline resumed: dag=%s dispatched=%d progress=%d%%",
            dag_id,
            len(dispatched),
            progress,
        )
        return {
            "dispatched_count": len(dispatched),
            "dispatched_job_ids": dispatched,
            "progress": progress,
        }

    async def _load_scan_config(self, scan_id: uuid.UUID) -> dict[str, Any]:
        result = await self._session.execute(
            text("SELECT config FROM scans WHERE id = :id"),
            {"id": str(scan_id)},
        )
        value = result.scalar_one_or_none()
        return value if isinstance(value, dict) else {}

    async def _run_ai_strategy_advisor(
        self,
        *,
        scan_id: uuid.UUID,
        dag_id: uuid.UUID,
        tenant_id: uuid.UUID,
        phase_completed: int,
    ) -> StrategyRecommendation | None:
        """Run the AI strategy advisor after a phase completes.

        The advisor analyzes findings and recommends next steps.
        Recommendations are stored as scan artifacts for the strategy-log API.
        """
        try:
            scan_config = await self._load_scan_config(scan_id)

            # Get phase name
            phase_result = await self._session.execute(
                text("SELECT name FROM scan_phases WHERE dag_id = :did AND phase_number = :pn"),
                {"did": str(dag_id), "pn": phase_completed},
            )
            phase_name = (phase_result.scalar_one_or_none() or f"phase_{phase_completed}")

            # Gather findings from completed phase
            findings_result = await self._session.execute(
                text("""
                    SELECT a.metadata FROM scan_artifacts a
                    JOIN scan_nodes n ON n.id = a.node_id
                    JOIN scan_phases p ON p.id = n.phase_id
                    WHERE a.scan_id = :scan_id AND p.phase_number = :pn
                """),
                {"scan_id": str(scan_id), "pn": phase_completed},
            )
            findings = [
                row[0] for row in findings_result.all()
                if row[0] and isinstance(row[0], dict)
            ]

            # Extend the scan lock before the LLM call — AI advisor can
            # take 10-30s and we must not let the lock expire mid-operation.
            from app.engine.concurrency_controller import ConcurrencyController
            cc = ConcurrencyController(self._redis)
            await cc.extend_scan_lock(scan_id, holder="orchestrator")

            # Call the advisor
            recommendation = await self._advisor.recommend(
                scan_id=scan_id,
                phase_completed=phase_completed,
                phase_name=phase_name,
                findings=findings,
                scan_config=scan_config,
            )

            # Store the recommendation as an artifact for strategy-log API
            if recommendation and not recommendation.error:
                await self._store_strategy_artifact(
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    phase_completed=phase_completed,
                    recommendation=recommendation,
                )

            return recommendation

        except Exception:
            logger.exception("AI strategy advisor failed for scan %s", scan_id)
            return None

    async def _apply_ai_planner(
        self,
        *,
        dag_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        phase_completed: int,
        recommendation: StrategyRecommendation,
        active_phase_tool_ids: list[str] | None = None,
        target: str,
        priority: str,
    ) -> dict[str, Any]:
        """Build and apply a measurable planner mutation when autonomy is enabled."""
        try:
            if _autonomy_disabled():
                return {
                    "status": "autonomy_disabled",
                    "created_node_ids": [],
                    "job_ids": [],
                    "suppressed_tool_ids": [],
                    "suppressed_node_ids": [],
                    "planner_actions": [],
                    "dispatched_tools": [],
                    "target_model_summary": None,
                    "capability_advisories": [],
                    "strategic_plan": None,
                    "tactical_plan": None,
                    "measurable_effect_expected": False,
                }

            if recommendation.phase_decision == "skip_to_report":
                return {
                    "status": "phase_decision_skipped",
                    "created_node_ids": [],
                    "job_ids": [],
                    "suppressed_tool_ids": [],
                    "suppressed_node_ids": [],
                    "planner_actions": [],
                    "dispatched_tools": [],
                    "target_model_summary": None,
                    "capability_advisories": [],
                    "strategic_plan": None,
                    "tactical_plan": None,
                    "measurable_effect_expected": False,
                }

            dag_runtime = await self._load_dag_runtime(dag_id)
            if dag_runtime is None:
                return {
                    "status": "missing_dag_runtime",
                    "created_node_ids": [],
                    "job_ids": [],
                    "suppressed_tool_ids": [],
                    "suppressed_node_ids": [],
                    "planner_actions": [],
                    "dispatched_tools": [],
                    "target_model_summary": None,
                    "capability_advisories": [],
                    "strategic_plan": None,
                    "tactical_plan": None,
                    "measurable_effect_expected": False,
                }

            scan_config = await self._load_scan_config(scan_id)
            template_tool_catalog = await self._load_template_tool_catalog(
                scan_type=str(dag_runtime["scan_type"]),
                asset_type=str(dag_runtime["asset_type"]),
                scan_config=scan_config,
            )
            target_model_summary = await self._target_model_loader.load(
                scan_id=scan_id,
                tenant_id=tenant_id,
            )
            capability_advisories = await self._run_capability_advisory(
                scan_id=scan_id,
                tenant_id=tenant_id,
                phase_completed=phase_completed,
                target_model_summary=target_model_summary,
            )
            strategic_plan = self._strategic_planner.build_plan(
                StrategicPlannerContext(
                    scan_id=str(scan_id),
                    dag_id=str(dag_id),
                    scan_type=str(dag_runtime["scan_type"]),
                    asset_type=str(dag_runtime["asset_type"]),
                    phase_completed=phase_completed,
                    current_progress=await self._state.update_scan_progress(scan_id),
                    template_node_count=len(template_tool_catalog),
                    template_tool_ids=[str(item["tool"]) for item in template_tool_catalog],
                    active_phase_tool_ids=_string_list(active_phase_tool_ids),
                    recommendation=recommendation,
                    target_model=target_model_summary,
                )
            )
            tactical_plan = self._tactical_planner.build_plan(
                strategic_plan=strategic_plan,
                recommendation=recommendation,
                scan_type=str(dag_runtime["scan_type"]),
                asset_type=str(dag_runtime["asset_type"]),
                scan_config=scan_config,
            )
            mutation_result = await self._plan_mutator.apply(
                dag_id=dag_id,
                scan_id=scan_id,
                tenant_id=tenant_id,
                tactical_plan=tactical_plan,
                target=target,
                priority=priority,
                scan_config=scan_config,
            )
            return {
                "status": mutation_result.status,
                "planner_decision": strategic_plan.decision,
                "planner_objective": strategic_plan.objective,
                "mutation_kind": mutation_result.mutation_kind,
                "expected_path_change": mutation_result.expected_path_change,
                "planner_actions": [action.to_dict() for action in strategic_plan.actions],
                "created_node_ids": mutation_result.created_node_ids,
                "job_ids": mutation_result.dispatched_job_ids,
                "dispatched_tools": mutation_result.dispatched_tools,
                "suppressed_tool_ids": mutation_result.suppressed_tool_ids,
                "suppressed_node_ids": mutation_result.suppressed_node_ids,
                "target_model_summary": target_model_summary.to_dict(),
                "capability_advisories": capability_advisories,
                "strategic_plan": strategic_plan.to_dict(),
                "tactical_plan": tactical_plan.to_dict(),
                "measurable_effect_expected": strategic_plan.measurable_effect_expected,
            }
        except Exception:
            logger.exception("R3 planner application failed for scan %s", scan_id)
            return {
                "status": "planner_error",
                "created_node_ids": [],
                "job_ids": [],
                "suppressed_tool_ids": [],
                "suppressed_node_ids": [],
                "planner_actions": [],
                "dispatched_tools": [],
                "target_model_summary": None,
                "capability_advisories": [],
                "strategic_plan": None,
                "tactical_plan": None,
                "measurable_effect_expected": False,
            }

    async def _run_capability_advisory(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        phase_completed: int,
        target_model_summary: Any,
    ) -> list[dict[str, Any]]:
        advisory_refs = list(target_model_summary.advisory_artifact_refs or [])
        if not advisory_refs:
            return []
        try:
            responses = await self._capability_advisor.recommend_from_artifact_refs(
                artifact_refs=advisory_refs,
                target_model_summary=target_model_summary.to_dict(),
            )
            response_payloads = [response.model_dump(mode="json") for response in responses]
            for response_payload in response_payloads:
                await self._store_capability_advisory_artifact(
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    phase_completed=phase_completed,
                    response=response_payload,
                    target_model_summary=target_model_summary.to_dict(),
                )
            return response_payloads
        except Exception:
            logger.exception("Capability advisory execution failed for scan %s", scan_id)
            return []

    async def _store_planner_effect_artifact(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        phase_completed: int,
        recommendation: StrategyRecommendation,
        planner_result: dict[str, Any],
        ready_nodes_before_planner: list[ReadyNode],
        ready_nodes_after_planner: list[ReadyNode],
        static_dispatched_nodes: list[ReadyNode],
    ) -> None:
        """Persist a phase-boundary planner-effect artifact for live R3 proof."""
        import json
        from datetime import datetime, timezone
        from pentra_common.storage.retention import apply_artifact_retention_metadata

        try:
            artifact_id = uuid.uuid4()
            created_at = datetime.now(timezone.utc)
            storage_ref = (
                f"artifacts/{tenant_id}/{scan_id}/planner_effect/"
                f"planner_effect_phase_{phase_completed}_{artifact_id}.json"
            )
            ready_before = _ready_node_snapshots(ready_nodes_before_planner)
            ready_after = _ready_node_snapshots(ready_nodes_after_planner)
            static_dispatched = _ready_node_snapshots(static_dispatched_nodes)
            suppressed_tools = _string_list(planner_result.get("suppressed_tool_ids"))
            planner_actions = planner_result.get("planner_actions") or []
            target_model_summary = planner_result.get("target_model_summary")
            top_focus = (
                target_model_summary.get("top_focus")
                if isinstance(target_model_summary, dict)
                else None
            )
            suppression_detected = bool(
                suppressed_tools or planner_result.get("suppressed_node_ids")
            )
            dynamic_followup_detected = bool(
                planner_result.get("created_node_ids") or planner_result.get("job_ids")
            )
            target_model_pressure_detected = bool(
                isinstance(target_model_summary, dict)
                and target_model_summary.get("has_meaningful_pressure")
            )
            planner_effect_detected = bool(
                planner_actions
                and target_model_pressure_detected
                and (suppression_detected or dynamic_followup_detected)
            )

            metadata = apply_artifact_retention_metadata(
                {
                    "phase_completed": phase_completed,
                    "planner_decision": planner_result.get("planner_decision"),
                    "mutation_kind": planner_result.get("mutation_kind"),
                    "planner_status": planner_result.get("status"),
                    "planner_action_types": sorted(
                        {
                            str(item.get("action_type"))
                            for item in planner_actions
                            if isinstance(item, dict) and str(item.get("action_type") or "").strip()
                        }
                    ),
                    "planner_action_count": len(planner_actions),
                    "route_groups": sorted(
                        {
                            str(item.get("route_group"))
                            for item in planner_actions
                            if isinstance(item, dict) and str(item.get("route_group") or "").strip()
                        }
                    ),
                    "suppression_detected": suppression_detected,
                    "suppressed_tool_ids": suppressed_tools,
                    "suppressed_node_count": len(planner_result.get("suppressed_node_ids", [])),
                    "dynamic_followup_detected": dynamic_followup_detected,
                    "followup_node_count": len(planner_result.get("created_node_ids", [])),
                    "followup_job_count": len(planner_result.get("job_ids", [])),
                    "followup_dispatched_tools": _string_list(planner_result.get("dispatched_tools")),
                    "target_model_pressure_detected": target_model_pressure_detected,
                    "top_focus_route_group": (
                        str(top_focus.get("route_group"))
                        if isinstance(top_focus, dict) and str(top_focus.get("route_group") or "").strip()
                        else None
                    ),
                    "top_focus_score": (
                        int(top_focus.get("focus_score") or 0)
                        if isinstance(top_focus, dict)
                        else 0
                    ),
                    "ready_before_count": len(ready_before),
                    "ready_after_count": len(ready_after),
                    "static_dispatched_count": len(static_dispatched),
                    "planner_effect_detected": planner_effect_detected,
                    "summary": {
                        "decision": planner_result.get("planner_decision"),
                        "mutation_kind": planner_result.get("mutation_kind"),
                        "planner_action_count": len(planner_actions),
                        "suppressed_tools": suppressed_tools,
                        "followup_tools": _string_list(planner_result.get("dispatched_tools")),
                        "top_focus_route_group": (
                            str(top_focus.get("route_group"))
                            if isinstance(top_focus, dict) and str(top_focus.get("route_group") or "").strip()
                            else None
                        ),
                        "effect_detected": planner_effect_detected,
                    },
                },
                policy="advisory",
            )
            payload = {
                "artifact_id": str(artifact_id),
                "scan_id": str(scan_id),
                "tenant_id": str(tenant_id),
                "artifact_type": "planner_effect",
                "created_at": created_at.isoformat(),
                "phase_completed": phase_completed,
                "recommendation": recommendation.to_dict(),
                "target_model_summary": target_model_summary,
                "strategic_plan": planner_result.get("strategic_plan"),
                "tactical_plan": planner_result.get("tactical_plan"),
                "mutation_result": {
                    "status": planner_result.get("status"),
                    "mutation_kind": planner_result.get("mutation_kind"),
                    "expected_path_change": planner_result.get("expected_path_change"),
                    "created_node_ids": planner_result.get("created_node_ids", []),
                    "job_ids": planner_result.get("job_ids", []),
                    "dispatched_tools": planner_result.get("dispatched_tools", []),
                    "suppressed_tool_ids": planner_result.get("suppressed_tool_ids", []),
                    "suppressed_node_ids": planner_result.get("suppressed_node_ids", []),
                },
                "runtime_effect": {
                    "planner_effect_detected": planner_effect_detected,
                    "target_model_pressure_detected": target_model_pressure_detected,
                    "suppression_detected": suppression_detected,
                    "dynamic_followup_detected": dynamic_followup_detected,
                    "ready_nodes_before_planner": ready_before,
                    "ready_nodes_after_planner": ready_after,
                    "static_dispatched_nodes": static_dispatched,
                    "static_ready_tools_before_planner": _unique_node_tools(ready_before),
                    "static_ready_tools_after_planner": _unique_node_tools(ready_after),
                    "static_dispatched_tools": _unique_node_tools(static_dispatched),
                    "planner_followup_dispatched_tools": _string_list(planner_result.get("dispatched_tools")),
                    "all_dispatched_tools": _dedupe_preserve_order(
                        _unique_node_tools(static_dispatched)
                        + _string_list(planner_result.get("dispatched_tools"))
                    ),
                },
                "metadata": metadata,
            }
            await self._store_json_scan_artifact(
                artifact_id=artifact_id,
                scan_id=scan_id,
                tenant_id=tenant_id,
                artifact_type="planner_effect",
                storage_ref=storage_ref,
                created_at=created_at,
                payload=payload,
                metadata=metadata,
            )
        except Exception:
            logger.exception("Failed to store planner-effect artifact")

    async def _store_strategy_artifact(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        phase_completed: int,
        recommendation: StrategyRecommendation,
    ) -> None:
        """Store AI strategy recommendation as a scan artifact."""
        from datetime import datetime, timezone
        from pentra_common.storage.retention import apply_artifact_retention_metadata

        try:
            artifact_id = uuid.uuid4()
            created_at = datetime.now(timezone.utc)
            storage_ref = (
                f"artifacts/{tenant_id}/{scan_id}/strategy/"
                f"ai_strategy_phase_{phase_completed}_{artifact_id}.json"
            )
            metadata = apply_artifact_retention_metadata(
                {
                    "phase_completed": phase_completed,
                    "phase_decision": recommendation.phase_decision,
                    "recommended_tools": recommendation.recommended_tools,
                    "attack_vectors": recommendation.attack_vectors,
                    "endpoint_focus": recommendation.endpoint_focus,
                    "strategy_notes": recommendation.strategy_notes,
                    "confidence": recommendation.confidence,
                    "provider": recommendation.provider,
                    "model": recommendation.model,
                    "transport": recommendation.transport,
                    "duration_ms": recommendation.duration_ms,
                    "summary": {
                        "decision": recommendation.phase_decision,
                        "tools": len(recommendation.recommended_tools),
                        "vectors": recommendation.attack_vectors,
                    },
                },
                policy="advisory",
            )
            payload = {
                "artifact_id": str(artifact_id),
                "scan_id": str(scan_id),
                "tenant_id": str(tenant_id),
                "artifact_type": "ai_strategy",
                "created_at": created_at.isoformat(),
                "metadata": metadata,
                "recommendation": recommendation.to_dict(),
            }
            await self._store_json_scan_artifact(
                artifact_id=artifact_id,
                scan_id=scan_id,
                tenant_id=tenant_id,
                artifact_type="ai_strategy",
                storage_ref=storage_ref,
                created_at=created_at,
                payload=payload,
                metadata=metadata,
            )
        except Exception:
            logger.exception("Failed to store AI strategy artifact")

    async def _store_capability_advisory_artifact(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        phase_completed: int,
        response: dict[str, Any],
        target_model_summary: dict[str, Any],
    ) -> None:
        from datetime import datetime, timezone
        from pentra_common.storage.retention import apply_artifact_retention_metadata

        try:
            artifact_id = uuid.uuid4()
            created_at = datetime.now(timezone.utc)
            pack_key = str(response.get("pack_key") or "capability_pack").strip() or "capability_pack"
            storage_ref = (
                f"artifacts/{tenant_id}/{scan_id}/capability_advisory/"
                f"{pack_key}_phase_{phase_completed}_{artifact_id}.json"
            )
            metadata = apply_artifact_retention_metadata(
                {
                    "phase_completed": phase_completed,
                    "pack_key": pack_key,
                    "advisory_mode": response.get("advisory_mode"),
                    "provider": response.get("provider"),
                    "model": response.get("model"),
                    "transport": response.get("transport"),
                    "prompt_version": response.get("prompt_version"),
                    "duration_ms": response.get("duration_ms"),
                    "error": response.get("error"),
                    "focus_item_count": len(response.get("focus_items") or []),
                    "evidence_gap_count": len(response.get("evidence_gap_priorities") or []),
                    "summary": {
                        "pack_key": pack_key,
                        "advisory_mode": response.get("advisory_mode"),
                        "provider": response.get("provider"),
                        "transport": response.get("transport"),
                        "focus_item_count": len(response.get("focus_items") or []),
                    },
                },
                policy="advisory",
            )
            payload = {
                "artifact_id": str(artifact_id),
                "scan_id": str(scan_id),
                "tenant_id": str(tenant_id),
                "artifact_type": "capability_advisory",
                "created_at": created_at.isoformat(),
                "metadata": metadata,
                "response": response,
                "target_model_summary": {
                    "top_focus": target_model_summary.get("top_focus"),
                    "target_profile_hypotheses": target_model_summary.get("target_profile_hypotheses"),
                    "capability_pressures": target_model_summary.get("capability_pressures"),
                },
            }
            await self._store_json_scan_artifact(
                artifact_id=artifact_id,
                scan_id=scan_id,
                tenant_id=tenant_id,
                artifact_type="capability_advisory",
                storage_ref=storage_ref,
                created_at=created_at,
                payload=payload,
                metadata=metadata,
            )
            if self._events is not None and hasattr(self._events, "publish_advisory_update"):
                provider = str(response.get("provider") or "").strip() or None
                fallback_status = (
                    "deterministic"
                    if provider in {None, "", "heuristic"}
                    else "error"
                    if str(response.get("error") or "").strip()
                    else "healthy"
                )
                await self._events.publish_advisory_update(
                    scan_id,
                    pack_key=pack_key,
                    provider=provider,
                    model=str(response.get("model") or "").strip() or None,
                    transport=str(response.get("transport") or "").strip() or None,
                    fallback_status=fallback_status,
                    artifact_ref=storage_ref,
                    summary={
                        "summary": (
                            str(response.get("route_summary") or "").strip()
                            or f"{pack_key} advisory persisted"
                        ),
                        "focus_item_count": len(response.get("focus_items") or []),
                        "evidence_gap_count": len(response.get("evidence_gap_priorities") or []),
                    },
                )
        except Exception:
            logger.exception("Failed to store capability advisory artifact")

    async def _store_json_scan_artifact(
        self,
        *,
        artifact_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        artifact_type: str,
        storage_ref: str,
        created_at: Any,
        payload: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        import json
        from pentra_common.storage.artifacts import write_json_artifact

        size_bytes, checksum = write_json_artifact(storage_ref, payload)
        await self._session.execute(
            text(
                """
                INSERT INTO scan_artifacts (
                    id, scan_id, tenant_id, artifact_type,
                    storage_ref, content_type, size_bytes,
                    checksum, metadata, created_at
                )
                VALUES (
                    :id, :scan_id, :tid, :artifact_type, :ref, 'application/json',
                    :size_bytes, :checksum, CAST(:metadata AS jsonb), :now
                )
                """
            ),
            {
                "id": str(artifact_id),
                "scan_id": str(scan_id),
                "tid": str(tenant_id),
                "artifact_type": artifact_type,
                "ref": storage_ref,
                "size_bytes": size_bytes,
                "checksum": checksum,
                "metadata": json.dumps(metadata),
                "now": created_at,
            },
        )
        await self._session.flush()

    async def _load_dag_runtime(self, dag_id: uuid.UUID) -> dict[str, Any] | None:
        result = await self._session.execute(
            text(
                """
                SELECT scan_type, asset_type, current_phase
                FROM scan_dags
                WHERE id = :id
                """
            ),
            {"id": str(dag_id)},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return {
            "scan_type": row["scan_type"],
            "asset_type": row["asset_type"],
            "current_phase": row["current_phase"],
        }

    async def _load_template_tool_catalog(
        self,
        *,
        scan_type: str,
        asset_type: str,
        scan_config: dict[str, Any],
    ) -> list[dict[str, str]]:
        from app.engine.dag_builder import get_tool_catalog

        return [
            {
                "tool": tool.name,
                "worker_family": tool.worker_family,
            }
            for tool in get_tool_catalog(scan_type, asset_type, scan_config)
        ]


def _ready_node_snapshots(nodes: list[ReadyNode]) -> list[dict[str, Any]]:
    return [
        {
            "node_id": str(node.node_id),
            "tool": node.tool,
            "worker_family": node.worker_family,
            "planner_action_type": str(node.config.get("planner_action_type") or "").strip(),
            "planner_route_group": str(node.config.get("planner_route_group") or "").strip(),
            "ai_strategy_generated": bool(node.config.get("ai_strategy_generated")),
        }
        for node in nodes
    ]


def _unique_node_tools(nodes: list[dict[str, Any]]) -> list[str]:
    return _dedupe_preserve_order(
        [
            str(node.get("tool") or "").strip()
            for node in nodes
            if isinstance(node, dict) and str(node.get("tool") or "").strip()
        ]
    )


def _string_list(value: Any) -> list[str]:
    items = value if isinstance(value, list) else []
    result: list[str] = []
    seen: set[str] = set()
    for item in items:
        text_value = str(item).strip()
        key = text_value.lower()
        if not text_value or key in seen:
            continue
        seen.add(key)
        result.append(text_value)
    return result


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        key = value.lower()
        if not value or key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result
