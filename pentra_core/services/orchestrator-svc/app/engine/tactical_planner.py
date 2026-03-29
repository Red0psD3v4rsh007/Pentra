"""Phase 9 tactical planner.

Converts a strategic intent into concrete planned follow-up work that the
runtime can mutate into the current DAG.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.engine.ai_strategy_advisor import StrategyRecommendation
from app.engine.ai_strategy_followup_planner import (
    AIStrategyFollowupPlanner,
    PlannedAIStrategyFollowup,
)
from app.engine.strategic_planner import PlannerAction, StrategicPlan


@dataclass(frozen=True)
class TacticalPlan:
    """Concrete mutation candidate set for the active phase."""

    decision: str
    mutation_kind: str
    rationale: str
    actions: list[PlannerAction]
    planned_followups: list[PlannedAIStrategyFollowup]
    suppressed_tool_ids: list[str]
    expected_path_change: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "mutation_kind": self.mutation_kind,
            "rationale": self.rationale,
            "actions": [action.to_dict() for action in self.actions],
            "planned_followups": [
                {
                    "tool": item.tool,
                    "worker_family": item.worker_family,
                    "target_url": item.target_url,
                    "priority": item.priority,
                    "reason": item.reason,
                    "attack_vectors": list(item.attack_vectors),
                    "endpoint_focus": list(item.endpoint_focus),
                    "planner_action_type": item.planner_action_type,
                    "route_group": item.route_group,
                    "stop_condition": item.stop_condition,
                }
                for item in self.planned_followups
            ],
            "suppressed_tool_ids": list(self.suppressed_tool_ids),
            "expected_path_change": self.expected_path_change,
        }


class TacticalPlanner:
    """Map strategic intent into bounded runtime mutations."""

    def __init__(self, followup_planner: AIStrategyFollowupPlanner) -> None:
        self._followup_planner = followup_planner

    def build_plan(
        self,
        *,
        strategic_plan: StrategicPlan,
        recommendation: StrategyRecommendation,
        scan_type: str,
        asset_type: str,
        scan_config: dict[str, Any],
    ) -> TacticalPlan:
        if strategic_plan.decision not in {"expand_current_phase", "rebalance_phase"}:
            mutation_kind = "suppress_pending_tools" if strategic_plan.suppressed_tool_ids else "none"
            return TacticalPlan(
                decision=strategic_plan.decision,
                mutation_kind=mutation_kind,
                rationale=strategic_plan.rationale,
                actions=list(strategic_plan.actions),
                planned_followups=[],
                suppressed_tool_ids=list(strategic_plan.suppressed_tool_ids),
                expected_path_change=strategic_plan.expected_path_change,
            )

        planned_followups = _plan_followups_from_actions(
            followup_planner=self._followup_planner,
            actions=strategic_plan.actions,
            recommendation=recommendation,
            scan_type=scan_type,
            asset_type=asset_type,
            scan_config=scan_config,
        )
        mutation_kind = _mutation_kind(
            planned_followups=planned_followups,
            suppressed_tool_ids=strategic_plan.suppressed_tool_ids,
        )
        return TacticalPlan(
            decision=strategic_plan.decision,
            mutation_kind=mutation_kind,
            rationale=strategic_plan.rationale,
            actions=list(strategic_plan.actions),
            planned_followups=planned_followups,
            suppressed_tool_ids=list(strategic_plan.suppressed_tool_ids),
            expected_path_change=strategic_plan.expected_path_change,
        )


def _plan_followups_from_actions(
    *,
    followup_planner: AIStrategyFollowupPlanner,
    actions: list[PlannerAction],
    recommendation: StrategyRecommendation,
    scan_type: str,
    asset_type: str,
    scan_config: dict[str, Any],
) -> list[PlannedAIStrategyFollowup]:
    planned: list[PlannedAIStrategyFollowup] = []
    seen: set[tuple[str, str]] = set()

    for action in actions:
        if not action.preferred_tool_ids:
            continue
        action_followups = followup_planner.plan_followups_for_tools(
            tool_ids=action.preferred_tool_ids,
            target_urls=action.target_urls,
            attack_vectors=recommendation.attack_vectors,
            reason=action.rationale,
            priority="high" if action.action_type == "verify_suspected_issue" else "medium",
            planner_action_type=action.action_type,
            route_group=action.route_group,
            hypothesis=action.hypothesis,
            stop_condition=action.stop_condition,
            prerequisite_evidence=action.prerequisite_evidence,
            scan_type=scan_type,
            asset_type=asset_type,
            scan_config=scan_config,
            recommendation=recommendation,
        )
        for followup in action_followups:
            key = (followup.tool, followup.target_url or followup.route_group)
            if key in seen:
                continue
            seen.add(key)
            planned.append(followup)
    return planned


def _mutation_kind(
    *,
    planned_followups: list[PlannedAIStrategyFollowup],
    suppressed_tool_ids: list[str],
) -> str:
    if planned_followups and suppressed_tool_ids:
        return "rebalance_phase"
    if planned_followups:
        return "insert_dynamic_followups"
    if suppressed_tool_ids:
        return "suppress_pending_tools"
    return "none"
