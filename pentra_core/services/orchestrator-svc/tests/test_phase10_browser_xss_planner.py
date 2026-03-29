from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_phase10_strategic_planner_prefers_browser_xss_route_actions() -> None:
    from app.engine.ai_strategy_advisor import StrategyRecommendation
    from app.engine.planner_target_model_loader import PlannerRouteGroupSummary, PlannerTargetModelSummary
    from app.engine.strategic_planner import StrategicPlanner, StrategicPlannerContext

    planner = StrategicPlanner()
    recommendation = StrategyRecommendation(
        recommended_tools=[{"tool_id": "nuclei", "priority": "low"}],
        attack_vectors=["xss"],
        endpoint_focus=["http://127.0.0.1:3001/#/search?q=demo"],
        phase_decision="proceed",
        strategy_notes="Browser route shows DOM sink pressure.",
        confidence=0.78,
    )
    target_model = PlannerTargetModelSummary(
        route_group_count=1,
        auth_surface_count=0,
        parameter_count=1,
        workflow_edge_count=0,
        source_artifact_types=["endpoints"],
        route_groups=[
            PlannerRouteGroupSummary(
                route_group="/#/search",
                focus_score=11,
                requires_auth=False,
                auth_variants=["unauthenticated"],
                parameter_names=["q"],
                endpoint_urls=["http://127.0.0.1:3001/#/search?q=demo"],
                workflow_edge_count=0,
                interaction_kinds=["xss_candidate", "page"],
                safe_replay=False,
                vulnerability_types=["xss"],
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
                    "high": 0,
                    "medium": 1,
                    "low": 0,
                    "info": 0,
                },
                evidence_gaps=["verification"],
            )
        ],
    )

    plan = planner.build_plan(
        StrategicPlannerContext(
            scan_id="scan-xss",
            dag_id="dag-xss",
            scan_type="full",
            asset_type="web",
            phase_completed=2,
            current_progress=51,
            template_node_count=4,
            template_tool_ids=["web_interact", "custom_poc", "nuclei"],
            active_phase_tool_ids=["web_interact", "custom_poc", "nuclei"],
            recommendation=recommendation,
            target_model=target_model,
        )
    )

    assert "web_interact" in plan.recommended_tool_ids
    assert "custom_poc" in plan.recommended_tool_ids
    assert any(action.action_type == "stage_route_specific_xss_payloads" for action in plan.actions)


def test_phase10_strategic_planner_uses_browser_xss_route_pressure_without_finding() -> None:
    from app.engine.ai_strategy_advisor import StrategyRecommendation
    from app.engine.planner_target_model_loader import PlannerRouteGroupSummary, PlannerTargetModelSummary
    from app.engine.strategic_planner import StrategicPlanner, StrategicPlannerContext

    planner = StrategicPlanner()
    recommendation = StrategyRecommendation(
        recommended_tools=[],
        attack_vectors=["xss"],
        endpoint_focus=["http://127.0.0.1:3001/#/profile?name=demo"],
        phase_decision="proceed",
        strategy_notes="Client-side route exposes source and sink pressure but no verified finding yet.",
        confidence=0.74,
    )
    target_model = PlannerTargetModelSummary(
        route_group_count=1,
        auth_surface_count=0,
        parameter_count=2,
        workflow_edge_count=0,
        source_artifact_types=["endpoints"],
        route_groups=[
            PlannerRouteGroupSummary(
                route_group="/#/profile",
                focus_score=7,
                requires_auth=False,
                auth_variants=["unauthenticated"],
                parameter_names=["name", "q"],
                endpoint_urls=["http://127.0.0.1:3001/#/profile?name=demo"],
                workflow_edge_count=0,
                interaction_kinds=["xss_route_assessment", "xss_route_pressure"],
                safe_replay=False,
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
                evidence_gaps=["input_binding", "route_parameter_selection"],
            )
        ],
    )

    plan = planner.build_plan(
        StrategicPlannerContext(
            scan_id="scan-xss-pressure",
            dag_id="dag-xss-pressure",
            scan_type="full",
            asset_type="web",
            phase_completed=2,
            current_progress=54,
            template_node_count=4,
            template_tool_ids=["web_interact", "custom_poc", "nuclei"],
            active_phase_tool_ids=["web_interact", "custom_poc", "nuclei"],
            recommendation=recommendation,
            target_model=target_model,
        )
    )

    assert "web_interact" in plan.recommended_tool_ids
    assert "custom_poc" in plan.recommended_tool_ids
    assert any(action.action_type == "map_client_side_sinks" for action in plan.actions)
