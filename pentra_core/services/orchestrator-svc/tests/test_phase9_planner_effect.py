from __future__ import annotations

import asyncio
import os
import sys
import uuid


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_strategic_planner_rebalances_phase_from_target_model_pressure() -> None:
    from app.engine.ai_strategy_advisor import StrategyRecommendation
    from app.engine.planner_target_model_loader import (
        PlannerRouteGroupSummary,
        PlannerTargetModelSummary,
    )
    from app.engine.strategic_planner import StrategicPlanner, StrategicPlannerContext

    planner = StrategicPlanner()
    recommendation = StrategyRecommendation(
        recommended_tools=[
            {"tool_id": "sqlmap", "priority": "high"},
            {"tool_id": "sqlmap", "priority": "medium"},
            {"tool_id": "nuclei", "priority": "medium"},
        ],
        attack_vectors=["sqli", "idor"],
        endpoint_focus=["https://demo.test/api/users?id=7"],
        phase_decision="proceed",
        strategy_notes="Focus on the user endpoint and verify injection paths.",
        confidence=0.82,
    )
    target_model = PlannerTargetModelSummary(
        route_group_count=2,
        auth_surface_count=1,
        parameter_count=3,
        workflow_edge_count=1,
        source_artifact_types=["endpoints"],
        route_groups=[
            PlannerRouteGroupSummary(
                route_group="/api/users/{id}",
                focus_score=14,
                requires_auth=True,
                auth_variants=["admin"],
                parameter_names=["id"],
                endpoint_urls=["https://demo.test/api/users?id=7"],
                workflow_edge_count=1,
                interaction_kinds=["page"],
                safe_replay=False,
                vulnerability_types=["idor"],
                truth_counts={
                    "observed": 0,
                    "suspected": 1,
                    "reproduced": 0,
                    "verified": 0,
                    "rejected": 0,
                    "expired": 0,
                },
                severity_counts={
                    "critical": 0,
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
                evidence_gaps=["verification"],
            )
        ],
    )

    plan = planner.build_plan(
        StrategicPlannerContext(
            scan_id="scan-1",
            dag_id="dag-1",
            scan_type="full",
            asset_type="api",
            phase_completed=2,
            current_progress=47,
            template_node_count=6,
            template_tool_ids=["httpx_probe", "web_interact", "ffuf", "nuclei", "sqlmap", "nikto"],
            active_phase_tool_ids=["nuclei", "sqlmap", "nikto"],
            recommendation=recommendation,
            target_model=target_model,
        )
    )

    assert plan.decision == "rebalance_phase"
    assert plan.expected_path_change == "rebalance_phase"
    assert "web_interact" in plan.recommended_tool_ids
    assert "sqlmap" in plan.recommended_tool_ids
    assert "nuclei" in plan.suppressed_tool_ids
    assert "nikto" in plan.suppressed_tool_ids
    assert plan.measurable_effect_expected is True
    assert {action.action_type for action in plan.actions} == {
        "deepen_auth_context_probe",
        "pause_noisy_tool_family",
    }


def test_strategic_planner_rebalances_phase_from_prefinding_artifact_pressure() -> None:
    from app.engine.ai_strategy_advisor import StrategyRecommendation
    from app.engine.planner_target_model_loader import (
        PlannerRouteGroupSummary,
        PlannerTargetModelSummary,
    )
    from app.engine.strategic_planner import StrategicPlanner, StrategicPlannerContext

    planner = StrategicPlanner()
    recommendation = StrategyRecommendation(
        recommended_tools=[{"tool_id": "nuclei", "priority": "high"}],
        attack_vectors=[],
        endpoint_focus=[],
        phase_decision="proceed",
        strategy_notes="Enumeration found several routes. Running vulnerability scanners.",
        confidence=0.6,
    )
    target_model = PlannerTargetModelSummary(
        route_group_count=3,
        auth_surface_count=3,
        parameter_count=4,
        workflow_edge_count=5,
        source_artifact_types=["endpoints"],
        route_groups=[
            PlannerRouteGroupSummary(
                route_group="/login",
                focus_score=10,
                requires_auth=True,
                auth_variants=["admin", "john", "unauthenticated"],
                parameter_names=["username", "password", "csrf_token"],
                endpoint_urls=["https://demo.test/login"],
                workflow_edge_count=1,
                interaction_kinds=["form"],
                safe_replay=True,
                vulnerability_types=[],
                truth_counts={
                    "observed": 0,
                    "suspected": 0,
                    "reproduced": 0,
                    "verified": 0,
                    "rejected": 0,
                    "expired": 0,
                },
                severity_counts={
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
                evidence_gaps=["parameter_mapping"],
            )
        ],
    )

    plan = planner.build_plan(
        StrategicPlannerContext(
            scan_id="scan-2",
            dag_id="dag-2",
            scan_type="full",
            asset_type="api",
            phase_completed=2,
            current_progress=42,
            template_node_count=6,
            template_tool_ids=["httpx_probe", "web_interact", "ffuf", "nuclei", "sqlmap", "nikto"],
            active_phase_tool_ids=["nuclei", "sqlmap", "nikto"],
            recommendation=recommendation,
            target_model=target_model,
        )
    )

    assert plan.decision == "rebalance_phase"
    assert "sqlmap" in plan.recommended_tool_ids
    assert "web_interact" in plan.recommended_tool_ids
    assert set(plan.suppressed_tool_ids) == {"nuclei", "nikto"}
    assert any(action.action_type == "deepen_auth_context_probe" for action in plan.actions)


def test_tactical_planner_builds_rebalanced_followup_plan() -> None:
    from app.engine.ai_strategy_advisor import StrategyRecommendation
    from app.engine.ai_strategy_followup_planner import PlannedAIStrategyFollowup
    from app.engine.strategic_planner import PlannerAction, StrategicPlan
    from app.engine.tactical_planner import TacticalPlanner

    planned_followup = PlannedAIStrategyFollowup(
        tool="sqlmap",
        worker_family="vuln",
        target_url="https://demo.test/api/users?id=7",
        priority="high",
        reason="verify the likely injection point",
        attack_vectors=["sqli"],
        endpoint_focus=["https://demo.test/api/users?id=7"],
        config={"selected_checks": {"sqlmap": {"path": "https://demo.test/api/users?id=7"}}},
        planner_action_type="verify_suspected_issue",
        route_group="/api/users/{id}",
        stop_condition="stop after replayable proof or contradictory evidence is produced",
    )

    class _FakeFollowupPlanner:
        def plan_followups_for_tools(self, **kwargs):
            assert kwargs["tool_ids"] == ["sqlmap"]
            assert kwargs["target_urls"] == ["https://demo.test/api/users?id=7"]
            assert kwargs["planner_action_type"] == "verify_suspected_issue"
            assert kwargs["route_group"] == "/api/users/{id}"
            assert kwargs["scan_type"] == "full"
            assert kwargs["asset_type"] == "api"
            assert kwargs["scan_config"] == {"profile_id": "external_web_api_v1"}
            return [planned_followup]

    planner = TacticalPlanner(_FakeFollowupPlanner())  # type: ignore[arg-type]
    plan = planner.build_plan(
        strategic_plan=StrategicPlan(
            decision="rebalance_phase",
            objective="pressure sqli",
            rationale="Focus on the injection path.",
            expected_path_change="rebalance_phase",
            recommended_tool_ids=["sqlmap"],
            suppressed_tool_ids=["nuclei"],
            endpoint_focus=["https://demo.test/api/users?id=7"],
            attack_vectors=["sqli"],
            actions=[
                PlannerAction(
                    action_type="verify_suspected_issue",
                    route_group="/api/users/{id}",
                    objective="pressure sqli",
                    hypothesis="The route group is likely injectable.",
                    rationale="Focus on the injection path.",
                    target_urls=["https://demo.test/api/users?id=7"],
                    preferred_tool_ids=["sqlmap"],
                    suppressed_tool_ids=[],
                    prerequisite_evidence=["verification"],
                    expected_value="raise proof quality",
                    stop_condition="stop after replayable proof or contradictory evidence is produced",
                )
            ],
            measurable_effect_expected=True,
        ),
        recommendation=StrategyRecommendation(
            recommended_tools=[{"tool_id": "sqlmap"}],
            attack_vectors=["sqli"],
            endpoint_focus=["https://demo.test/api/users?id=7"],
            phase_decision="proceed",
            strategy_notes="Focus on the injection path.",
            confidence=0.8,
        ),
        scan_type="full",
        asset_type="api",
        scan_config={"profile_id": "external_web_api_v1"},
    )

    assert plan.mutation_kind == "rebalance_phase"
    assert plan.suppressed_tool_ids == ["nuclei"]
    assert len(plan.planned_followups) == 1
    assert plan.planned_followups[0].tool == "sqlmap"


def test_plan_mutator_dispatches_only_created_ready_followups() -> None:
    from app.engine.ai_strategy_followup_planner import PlannedAIStrategyFollowup
    from app.engine.dependency_resolver import ReadyNode
    from app.engine.plan_mutator import PlanMutator
    from app.engine.strategic_planner import PlannerAction
    from app.engine.tactical_planner import TacticalPlan

    dag_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    scan_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    tenant_id = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    created_node_id = uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
    ignored_node_id = uuid.UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")
    job_id = uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
    suppressed_node_id = uuid.UUID("12121212-1212-1212-1212-121212121212")

    planned_followup = PlannedAIStrategyFollowup(
        tool="sqlmap",
        worker_family="vuln",
        target_url="https://demo.test/api/users?id=7",
        priority="high",
        reason="verify likely injection",
        attack_vectors=["sqli"],
        endpoint_focus=["https://demo.test/api/users?id=7"],
        config={"ai_strategy_generated": True},
        planner_action_type="verify_suspected_issue",
        route_group="/api/users/{id}",
    )

    class _FakeFollowupPlanner:
        async def apply_plans(self, **kwargs):
            assert kwargs["dag_id"] == dag_id
            assert kwargs["tenant_id"] == tenant_id
            assert kwargs["plans"] == [planned_followup]
            return [created_node_id]

    class _FakeResolver:
        async def resolve_ready_nodes(self, requested_dag_id: uuid.UUID):
            assert requested_dag_id == dag_id
            return [
                ReadyNode(
                    node_id=created_node_id,
                    dag_id=dag_id,
                    phase_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
                    tool="sqlmap",
                    worker_family="vuln",
                    config={"ai_strategy_generated": True},
                    input_refs={},
                ),
                ReadyNode(
                    node_id=ignored_node_id,
                    dag_id=dag_id,
                    phase_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
                    tool="nuclei",
                    worker_family="vuln",
                    config={},
                    input_refs={},
                ),
            ]

    class _FakeDispatcher:
        async def dispatch_nodes(self, nodes, **kwargs):
            assert len(nodes) == 1
            assert nodes[0].node_id == created_node_id
            assert kwargs["scan_id"] == scan_id
            assert kwargs["tenant_id"] == tenant_id
            assert kwargs["target"] == "https://demo.test"
            assert kwargs["priority"] == "high"
            assert kwargs["config"] == {"profile_id": "external_web_api_v1"}
            return [job_id]

    class _FakeSession:
        def __init__(self) -> None:
            self.statements: list[str] = []

        async def execute(self, statement, params=None):
            self.statements.append(str(statement))

            class _Result:
                def all(self_inner):
                    return [(str(suppressed_node_id),)]

            return _Result()

        async def flush(self):
            return None

    mutator = PlanMutator(
        session=_FakeSession(),  # type: ignore[arg-type]
        followup_planner=_FakeFollowupPlanner(),  # type: ignore[arg-type]
        resolver=_FakeResolver(),  # type: ignore[arg-type]
        dispatcher=_FakeDispatcher(),  # type: ignore[arg-type]
    )
    result = asyncio.run(
        mutator.apply(
            dag_id=dag_id,
            scan_id=scan_id,
            tenant_id=tenant_id,
            tactical_plan=TacticalPlan(
                decision="rebalance_phase",
                mutation_kind="rebalance_phase",
                rationale="Focus on the injection path.",
                actions=[
                    PlannerAction(
                        action_type="verify_suspected_issue",
                        route_group="/api/users/{id}",
                        objective="verify likely injection",
                        hypothesis="The route group is likely injectable.",
                        rationale="Focus on the injection path.",
                        target_urls=["https://demo.test/api/users?id=7"],
                        preferred_tool_ids=["sqlmap"],
                        suppressed_tool_ids=[],
                        prerequisite_evidence=["verification"],
                        expected_value="raise proof quality",
                        stop_condition="stop after replayable proof or contradictory evidence is produced",
                    )
                ],
                planned_followups=[planned_followup],
                suppressed_tool_ids=["nuclei"],
                expected_path_change="rebalance_phase",
            ),
            target="https://demo.test",
            priority="high",
            scan_config={"profile_id": "external_web_api_v1"},
        )
    )

    assert result.status == "dispatched"
    assert result.created_node_ids == [created_node_id]
    assert result.dispatched_job_ids == [job_id]
    assert result.dispatched_tools == ["sqlmap"]
    assert result.suppressed_tool_ids == ["nuclei"]
    assert result.suppressed_node_ids == [suppressed_node_id]
