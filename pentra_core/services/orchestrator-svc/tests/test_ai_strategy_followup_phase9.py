from __future__ import annotations

import asyncio
import os
import sys
import uuid

from pentra_common.config.settings import Settings


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_followup_planner_builds_bounded_supported_followups() -> None:
    from app.engine.ai_strategy_advisor import StrategyRecommendation
    from app.engine.ai_strategy_followup_planner import AIStrategyFollowupPlanner

    planner = AIStrategyFollowupPlanner(
        session=None,  # type: ignore[arg-type]
        settings=Settings(max_ai_strategy_followups=2),
    )
    recommendation = StrategyRecommendation(
        recommended_tools=[
            {
                "tool_id": "sqlmap",
                "target_url": "https://demo.test/api/users?id=7",
                "reason": "verify possible injection point",
                "priority": "high",
            },
            {
                "tool_id": "nuclei",
                "reason": "focus on API attack vectors",
                "priority": "medium",
            },
            {
                "tool_id": "report_gen",
                "reason": "derived tool should not be materialized",
                "priority": "low",
            },
        ],
        attack_vectors=["sqli", "graphql", "idor"],
        endpoint_focus=["https://demo.test/api/users?id=7"],
        phase_decision="proceed",
        strategy_notes="Narrow into the user API surface.",
        confidence=0.91,
    )

    followups = planner.plan_followups(
        recommendation=recommendation,
        scan_type="full",
        asset_type="api",
        scan_config={"profile_id": "external_web_api_v1"},
    )

    assert [item.tool for item in followups] == ["sqlmap", "nuclei"]
    assert followups[0].config["selected_checks"]["sqlmap"]["path"] == "https://demo.test/api/users?id=7"
    assert followups[1].config["command_context"]["nuclei_tags"] == "sqli,graphql,idor"
    assert followups[0].config["planner_action_type"] == "expand_route_family"


def test_pipeline_executor_dispatches_ai_strategy_followups_when_enabled(monkeypatch) -> None:
    from app.engine.ai_strategy_advisor import StrategyRecommendation
    from app.engine.planner_target_model_loader import (
        PlannerRouteGroupSummary,
        PlannerTargetModelSummary,
    )
    from app.engine.plan_mutator import PlanMutationResult
    from app.engine.pipeline_executor import PipelineExecutor
    from app.engine.strategic_planner import PlannerAction, StrategicPlan
    from app.engine.tactical_planner import TacticalPlan

    dag_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    scan_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    tenant_id = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    created_node_id = uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
    job_id = uuid.UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")

    monkeypatch.setattr(
        "app.engine.pipeline_executor._autonomy_disabled",
        lambda: False,
    )

    recommendation = StrategyRecommendation(
        recommended_tools=[{"tool_id": "sqlmap", "priority": "high"}],
        attack_vectors=["sqli"],
        endpoint_focus=["https://demo.test/api/users?id=7"],
        phase_decision="deep_dive",
        strategy_notes="Deep dive into the user endpoint.",
        confidence=0.88,
    )

    class _FakeProgressState:
        async def update_scan_progress(self, requested_scan_id: uuid.UUID) -> int:
            assert requested_scan_id == scan_id
            return 61

    class _FakeStrategicPlanner:
        def build_plan(self, context):
            assert context.scan_id == str(scan_id)
            assert context.dag_id == str(dag_id)
            assert context.scan_type == "full"
            assert context.asset_type == "api"
            assert context.template_node_count == 3
            assert context.template_tool_ids == ["httpx_probe", "nuclei", "sqlmap"]
            assert context.active_phase_tool_ids == ["nuclei", "sqlmap"]
            assert context.recommendation is recommendation
            assert context.target_model is not None
            return StrategicPlan(
                decision="rebalance_phase",
                objective="pressure sqli",
                rationale="Deep dive into the user endpoint.",
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
                        rationale="Deep dive into the user endpoint.",
                        target_urls=["https://demo.test/api/users?id=7"],
                        preferred_tool_ids=["sqlmap"],
                        suppressed_tool_ids=[],
                        prerequisite_evidence=["verification"],
                        expected_value="raise proof quality",
                        stop_condition="stop after replayable proof or contradictory evidence is produced",
                    )
                ],
                measurable_effect_expected=True,
            )

    class _FakeTacticalPlanner:
        def build_plan(self, *, strategic_plan, recommendation: StrategyRecommendation, scan_type: str, asset_type: str, scan_config):
            assert strategic_plan.decision == "rebalance_phase"
            assert recommendation is not None
            assert recommendation.phase_decision == "deep_dive"
            assert scan_type == "full"
            assert asset_type == "api"
            assert scan_config == {"profile_id": "external_web_api_v1"}
            return TacticalPlan(
                decision="rebalance_phase",
                mutation_kind="rebalance_phase",
                rationale=strategic_plan.rationale,
                actions=strategic_plan.actions,
                planned_followups=[],
                suppressed_tool_ids=["nuclei"],
                expected_path_change="rebalance_phase",
            )

    class _FakePlanMutator:
        async def apply(self, **kwargs):
            assert kwargs["dag_id"] == dag_id
            assert kwargs["scan_id"] == scan_id
            assert kwargs["tenant_id"] == tenant_id
            assert kwargs["target"] == "https://demo.test"
            assert kwargs["priority"] == "high"
            assert kwargs["scan_config"] == {"profile_id": "external_web_api_v1"}
            assert kwargs["tactical_plan"].mutation_kind == "rebalance_phase"
            return PlanMutationResult(
                status="dispatched",
                mutation_kind="rebalance_phase",
                planned_followup_count=1,
                created_node_ids=[created_node_id],
                dispatched_job_ids=[job_id],
                dispatched_tools=["sqlmap"],
                suppressed_tool_ids=["nuclei"],
                suppressed_node_ids=[],
                expected_path_change="rebalance_phase",
                rationale="Deep dive into the user endpoint.",
            )

    class _FakeTargetModelLoader:
        async def load(self, *, scan_id: uuid.UUID, tenant_id: uuid.UUID):
            assert scan_id == uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
            assert tenant_id == uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
            return PlannerTargetModelSummary(
                route_group_count=1,
                auth_surface_count=1,
                parameter_count=1,
                workflow_edge_count=0,
                source_artifact_types=["endpoints"],
                route_groups=[
                    PlannerRouteGroupSummary(
                        route_group="/api/users/{id}",
                        focus_score=12,
                        requires_auth=True,
                        auth_variants=["admin"],
                        parameter_names=["id"],
                        endpoint_urls=["https://demo.test/api/users?id=7"],
                        workflow_edge_count=0,
                        interaction_kinds=[],
                        safe_replay=False,
                        vulnerability_types=["sql_injection"],
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

    executor = PipelineExecutor(session=None, redis=None)  # type: ignore[arg-type]
    executor._state = _FakeProgressState()  # type: ignore[assignment]
    executor._strategic_planner = _FakeStrategicPlanner()  # type: ignore[assignment]
    executor._tactical_planner = _FakeTacticalPlanner()  # type: ignore[assignment]
    executor._plan_mutator = _FakePlanMutator()  # type: ignore[assignment]
    executor._target_model_loader = _FakeTargetModelLoader()  # type: ignore[assignment]

    async def fake_load_dag_runtime(requested_dag_id: uuid.UUID) -> dict[str, str]:
        assert requested_dag_id == dag_id
        return {"scan_type": "full", "asset_type": "api", "current_phase": "5"}

    async def fake_load_scan_config(requested_scan_id: uuid.UUID) -> dict[str, str]:
        assert requested_scan_id == scan_id
        return {"profile_id": "external_web_api_v1"}

    async def fake_load_template_tool_catalog(*, scan_type: str, asset_type: str, scan_config: dict[str, str]):
        assert scan_type == "full"
        assert asset_type == "api"
        assert scan_config == {"profile_id": "external_web_api_v1"}
        return [
            {"tool": "httpx_probe", "worker_family": "recon"},
            {"tool": "nuclei", "worker_family": "vuln"},
            {"tool": "sqlmap", "worker_family": "vuln"},
        ]

    executor._load_dag_runtime = fake_load_dag_runtime  # type: ignore[method-assign]
    executor._load_scan_config = fake_load_scan_config  # type: ignore[method-assign]
    executor._load_template_tool_catalog = fake_load_template_tool_catalog  # type: ignore[method-assign]

    result = asyncio.run(
        executor._apply_ai_planner(
            dag_id=dag_id,
            scan_id=scan_id,
            tenant_id=tenant_id,
            phase_completed=5,
            recommendation=recommendation,
            active_phase_tool_ids=["nuclei", "sqlmap"],
            target="https://demo.test",
            priority="high",
        )
    )

    assert result["status"] == "dispatched"
    assert result["planner_decision"] == "rebalance_phase"
    assert result["mutation_kind"] == "rebalance_phase"
    assert result["created_node_ids"] == [created_node_id]
    assert result["job_ids"] == [job_id]
    assert result["dispatched_tools"] == ["sqlmap"]
    assert result["suppressed_tool_ids"] == ["nuclei"]
    assert result["planner_actions"][0]["action_type"] == "verify_suspected_issue"
    assert result["target_model_summary"]["has_meaningful_pressure"] is True
    assert result["strategic_plan"]["decision"] == "rebalance_phase"
    assert result["tactical_plan"]["mutation_kind"] == "rebalance_phase"
    assert result["measurable_effect_expected"] is True


def test_pipeline_executor_stores_planner_effect_artifact_after_phase_boundary(monkeypatch) -> None:
    from app.engine.ai_strategy_advisor import StrategyRecommendation
    from app.engine.dependency_resolver import ReadyNode
    from app.engine.pipeline_executor import PipelineExecutor

    dag_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    scan_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    tenant_id = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    node_id = uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
    phase_id = uuid.UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")
    static_job_id = uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
    planner_job_id = uuid.UUID("12121212-1212-1212-1212-121212121212")

    monkeypatch.setattr(
        "app.engine.pipeline_executor._autonomy_disabled",
        lambda: False,
    )

    recommendation = StrategyRecommendation(
        recommended_tools=[{"tool_id": "sqlmap", "priority": "high"}],
        attack_vectors=["sqli"],
        endpoint_focus=["https://demo.test/api/users?id=7"],
        phase_decision="deep_dive",
        strategy_notes="Deep dive into the user endpoint.",
        confidence=0.88,
    )

    ready_nuclei = ReadyNode(
        node_id=uuid.UUID("13131313-1313-1313-1313-131313131313"),
        dag_id=dag_id,
        phase_id=phase_id,
        tool="nuclei",
        worker_family="vuln",
        config={},
        input_refs={},
    )
    ready_sqlmap = ReadyNode(
        node_id=uuid.UUID("14141414-1414-1414-1414-141414141414"),
        dag_id=dag_id,
        phase_id=phase_id,
        tool="sqlmap",
        worker_family="vuln",
        config={},
        input_refs={},
    )

    class _FakeState:
        async def store_artifact(self, **kwargs):
            assert kwargs["scan_id"] == scan_id
            assert kwargs["node_id"] == node_id
            assert kwargs["tenant_id"] == tenant_id

        async def update_scan_progress(self, requested_scan_id: uuid.UUID) -> int:
            assert requested_scan_id == scan_id
            return 88

    class _FakeResolver:
        async def resolve_ready_nodes(self, requested_dag_id: uuid.UUID):
            assert requested_dag_id == dag_id
            return []

    class _FakeController:
        async def evaluate_and_advance(self, requested_dag_id: uuid.UUID, current_phase: int):
            assert requested_dag_id == dag_id
            assert current_phase == 2
            return "executing", [ready_nuclei, ready_sqlmap], True

    class _FakeDispatcher:
        async def dispatch_nodes(self, nodes, **kwargs):
            assert [node.tool for node in nodes] == ["sqlmap"]
            assert kwargs["scan_id"] == scan_id
            assert kwargs["tenant_id"] == tenant_id
            assert kwargs["target"] == "https://demo.test"
            assert kwargs["priority"] == "high"
            return [static_job_id]

    captured: dict[str, object] = {}

    async def fake_run_ai_strategy_advisor(**kwargs):
        assert kwargs["scan_id"] == scan_id
        assert kwargs["dag_id"] == dag_id
        return recommendation

    async def fake_apply_ai_planner(**kwargs):
        assert kwargs["scan_id"] == scan_id
        assert kwargs["dag_id"] == dag_id
        return {
            "status": "dispatched",
            "planner_decision": "rebalance_phase",
            "planner_objective": "pressure sqli",
            "mutation_kind": "rebalance_phase",
            "expected_path_change": "rebalance_phase",
            "planner_actions": [
                {
                    "action_type": "verify_suspected_issue",
                    "route_group": "/api/users/{id}",
                    "target_urls": ["https://demo.test/api/users?id=7"],
                }
            ],
            "created_node_ids": [uuid.UUID("15151515-1515-1515-1515-151515151515")],
            "job_ids": [planner_job_id],
            "dispatched_tools": ["web_interact"],
            "suppressed_tool_ids": ["nuclei"],
            "suppressed_node_ids": [],
            "target_model_summary": {
                "has_meaningful_pressure": True,
                "top_focus": {"route_group": "/api/users/{id}", "focus_score": 12},
            },
            "strategic_plan": {"decision": "rebalance_phase"},
            "tactical_plan": {"mutation_kind": "rebalance_phase"},
            "measurable_effect_expected": True,
        }

    async def fake_load_scan_config(requested_scan_id: uuid.UUID) -> dict[str, str]:
        assert requested_scan_id == scan_id
        return {"profile_id": "external_web_api_v1"}

    async def fake_store_planner_effect_artifact(**kwargs):
        captured.update(kwargs)

    executor = PipelineExecutor(session=None, redis=None)  # type: ignore[arg-type]
    executor._state = _FakeState()  # type: ignore[assignment]
    executor._resolver = _FakeResolver()  # type: ignore[assignment]
    executor._controller = _FakeController()  # type: ignore[assignment]
    executor._dispatcher = _FakeDispatcher()  # type: ignore[assignment]
    executor._run_ai_strategy_advisor = fake_run_ai_strategy_advisor  # type: ignore[method-assign]
    executor._apply_ai_planner = fake_apply_ai_planner  # type: ignore[method-assign]
    executor._load_scan_config = fake_load_scan_config  # type: ignore[method-assign]
    executor._store_planner_effect_artifact = fake_store_planner_effect_artifact  # type: ignore[method-assign]

    result = asyncio.run(
        executor.execute_after_completion(
            dag_id=dag_id,
            scan_id=scan_id,
            tenant_id=tenant_id,
            node_id=node_id,
            phase_number=2,
            output_ref="artifacts/demo/result.json",
            output_summary={"artifact_type": "nuclei"},
            tool="nuclei",
            target="https://demo.test",
            priority="high",
            allow_dispatch=True,
        )
    )

    assert result["dispatched_count"] == 2
    assert result["progress"] == 88
    assert captured["phase_completed"] == 2
    assert captured["planner_result"]["planner_decision"] == "rebalance_phase"  # type: ignore[index]
    assert [node.tool for node in captured["ready_nodes_before_planner"]] == ["nuclei", "sqlmap"]  # type: ignore[index]
    assert [node.tool for node in captured["ready_nodes_after_planner"]] == ["sqlmap"]  # type: ignore[index]
    assert [node.tool for node in captured["static_dispatched_nodes"]] == ["sqlmap"]  # type: ignore[index]
