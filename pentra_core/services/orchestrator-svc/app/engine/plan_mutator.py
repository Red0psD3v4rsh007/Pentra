"""Phase 9 plan mutator.

Applies a tactical plan to the active DAG and returns measurable planner
effects so autonomy claims can be tied to runtime-visible mutations.
"""

from __future__ import annotations

from dataclasses import dataclass
import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.engine.ai_strategy_followup_planner import AIStrategyFollowupPlanner
from app.engine.dependency_resolver import DependencyResolver
from app.engine.job_dispatcher import JobDispatcher
from app.engine.tactical_planner import TacticalPlan


@dataclass(frozen=True)
class PlanMutationResult:
    """Result of applying a tactical plan to the DAG."""

    status: str
    mutation_kind: str
    planned_followup_count: int
    created_node_ids: list[uuid.UUID]
    dispatched_job_ids: list[uuid.UUID]
    dispatched_tools: list[str]
    suppressed_tool_ids: list[str]
    suppressed_node_ids: list[uuid.UUID]
    expected_path_change: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "mutation_kind": self.mutation_kind,
            "planned_followup_count": self.planned_followup_count,
            "created_node_ids": list(self.created_node_ids),
            "dispatched_job_ids": list(self.dispatched_job_ids),
            "dispatched_tools": list(self.dispatched_tools),
            "suppressed_tool_ids": list(self.suppressed_tool_ids),
            "suppressed_node_ids": list(self.suppressed_node_ids),
            "expected_path_change": self.expected_path_change,
            "rationale": self.rationale,
        }


class PlanMutator:
    """Apply tactical planner decisions to the current DAG."""

    def __init__(
        self,
        *,
        session: AsyncSession,
        followup_planner: AIStrategyFollowupPlanner,
        resolver: DependencyResolver,
        dispatcher: JobDispatcher,
    ) -> None:
        self._session = session
        self._followup_planner = followup_planner
        self._resolver = resolver
        self._dispatcher = dispatcher

    async def apply(
        self,
        *,
        dag_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        tactical_plan: TacticalPlan,
        target: str,
        priority: str,
        scan_config: dict[str, Any],
    ) -> PlanMutationResult:
        if tactical_plan.mutation_kind == "none":
            return PlanMutationResult(
                status="mutation_not_required",
                mutation_kind=tactical_plan.mutation_kind,
                planned_followup_count=len(tactical_plan.planned_followups),
                created_node_ids=[],
                dispatched_job_ids=[],
                dispatched_tools=[],
                suppressed_tool_ids=[],
                suppressed_node_ids=[],
                expected_path_change=tactical_plan.expected_path_change,
                rationale=tactical_plan.rationale,
            )

        suppressed_node_ids = await self._suppress_active_phase_tools(
            dag_id=dag_id,
            tool_ids=tactical_plan.suppressed_tool_ids,
        )

        if tactical_plan.mutation_kind == "suppress_pending_tools":
            return PlanMutationResult(
                status="tools_suppressed" if suppressed_node_ids else "no_tools_suppressed",
                mutation_kind=tactical_plan.mutation_kind,
                planned_followup_count=0,
                created_node_ids=[],
                dispatched_job_ids=[],
                dispatched_tools=[],
                suppressed_tool_ids=list(tactical_plan.suppressed_tool_ids),
                suppressed_node_ids=suppressed_node_ids,
                expected_path_change=tactical_plan.expected_path_change,
                rationale=tactical_plan.rationale,
            )

        created_node_ids = await self._followup_planner.apply_plans(
            dag_id=dag_id,
            tenant_id=tenant_id,
            plans=tactical_plan.planned_followups,
        )
        if not created_node_ids:
            return PlanMutationResult(
                status="no_followups_created",
                mutation_kind=tactical_plan.mutation_kind,
                planned_followup_count=len(tactical_plan.planned_followups),
                created_node_ids=[],
                dispatched_job_ids=[],
                dispatched_tools=[],
                suppressed_tool_ids=list(tactical_plan.suppressed_tool_ids),
                suppressed_node_ids=suppressed_node_ids,
                expected_path_change=tactical_plan.expected_path_change,
                rationale=tactical_plan.rationale,
            )

        ready_nodes = await self._resolver.resolve_ready_nodes(dag_id)
        created_node_set = set(created_node_ids)
        created_ready_nodes = [
            node for node in ready_nodes if node.node_id in created_node_set
        ]

        if not created_ready_nodes:
            return PlanMutationResult(
                status="followups_created_not_ready",
                mutation_kind=tactical_plan.mutation_kind,
                planned_followup_count=len(tactical_plan.planned_followups),
                created_node_ids=created_node_ids,
                dispatched_job_ids=[],
                dispatched_tools=[],
                suppressed_tool_ids=list(tactical_plan.suppressed_tool_ids),
                suppressed_node_ids=suppressed_node_ids,
                expected_path_change=tactical_plan.expected_path_change,
                rationale=tactical_plan.rationale,
            )

        dispatched_job_ids = await self._dispatcher.dispatch_nodes(
            created_ready_nodes,
            scan_id=scan_id,
            tenant_id=tenant_id,
            target=target,
            priority=priority,
            config=scan_config,
        )
        return PlanMutationResult(
            status="dispatched",
            mutation_kind=tactical_plan.mutation_kind,
            planned_followup_count=len(tactical_plan.planned_followups),
            created_node_ids=created_node_ids,
            dispatched_job_ids=dispatched_job_ids,
            dispatched_tools=[node.tool for node in created_ready_nodes],
            suppressed_tool_ids=list(tactical_plan.suppressed_tool_ids),
            suppressed_node_ids=suppressed_node_ids,
            expected_path_change=tactical_plan.expected_path_change,
            rationale=tactical_plan.rationale,
        )

    async def _suppress_active_phase_tools(
        self,
        *,
        dag_id: uuid.UUID,
        tool_ids: list[str],
    ) -> list[uuid.UUID]:
        if not tool_ids:
            return []

        placeholders = ", ".join(f":tool_{index}" for index, _ in enumerate(tool_ids))
        params: dict[str, Any] = {"did": str(dag_id)}
        for index, tool_id in enumerate(tool_ids):
            params[f"tool_{index}"] = tool_id

        result = await self._session.execute(
            text(
                f"""
                UPDATE scan_nodes
                SET status = 'skipped'
                WHERE id IN (
                    SELECT n.id
                    FROM scan_nodes n
                    JOIN scan_phases p ON p.id = n.phase_id
                    WHERE n.dag_id = :did
                      AND p.status = 'running'
                      AND n.status IN ('pending', 'ready')
                      AND n.tool IN ({placeholders})
                )
                RETURNING id
                """
            ),
            params,
        )
        suppressed = [uuid.UUID(str(row[0])) for row in result.all()]
        if suppressed:
            await self._session.flush()
        return suppressed
