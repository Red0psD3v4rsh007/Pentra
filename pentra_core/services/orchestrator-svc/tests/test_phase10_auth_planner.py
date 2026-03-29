from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_phase10_target_model_loader_builds_auth_capability_pressure() -> None:
    from app.engine.planner_target_model_loader import _build_planner_target_model

    artifact_entries = [
        {
            "artifact_type": "endpoints",
            "storage_ref": "artifacts/test/auth-capability.json",
            "payload": {
                "artifact_type": "endpoints",
                "items": [],
                "multi_role_stateful_auth_capability": {
                    "pack_key": "p3a_multi_role_stateful_auth",
                    "target_profile": "auth_heavy_admin_portal",
                    "target_profile_keys": [
                        "auth_heavy_admin_portal",
                        "spa_rest_api",
                        "workflow_heavy_commerce",
                    ],
                    "benchmark_target_keys": ["repo_demo_api"],
                    "challenge_family_keys": ["broken_authentication", "broken_access_control"],
                    "planner_action_keys": [
                        "compare_role_access",
                        "pressure_auth_tokens_and_login_flows",
                        "enumerate_privileged_api_surface",
                    ],
                    "proof_contract_keys": ["role_differential_access_contract"],
                    "candidate_count": 2,
                    "planner_hook_count": 2,
                    "ai_advisory_ready": True,
                    "advisory_context": {
                        "enabled": True,
                        "advisory_mode": "multi_role_auth_route_focus",
                    },
                    "route_assessment_counts": {
                        "role_differential_candidate": 1,
                        "auth_transition_pressure": 1,
                        "negative_evidence_routes": 0,
                    },
                    "route_assessments": [
                        {
                            "route_group": "/admin/users",
                            "page_url": "https://demo.test/admin/users",
                            "assessment_state": "role_differential_candidate",
                            "risk_score": 78,
                            "advisory_priority": 90,
                            "parameter_hypotheses": ["userId"],
                            "proof_contracts": ["role_differential_access_contract"],
                            "session_labels": ["user", "admin"],
                            "auth_states": ["authenticated", "elevated"],
                            "requires_auth": True,
                            "privileged_surface": True,
                            "evidence_gaps": ["verification"],
                        }
                    ],
                },
                "relationships": [],
            },
        }
    ]

    summary = _build_planner_target_model(findings=[], artifact_entries=artifact_entries)

    assert summary.capability_pressures
    assert summary.capability_pressures[0].pack_key == "p3a_multi_role_stateful_auth"
    assert summary.capability_pressures[0].pressure_score > 0
    assert summary.target_profile_hypotheses
    assert summary.target_profile_hypotheses[0].key == "auth_heavy_admin_portal"
    assert summary.advisory_artifact_refs[0]["pack_key"] == "p3a_multi_role_stateful_auth"

    top_focus = summary.top_focus
    assert top_focus is not None
    assert top_focus.route_group == "/admin/users"
    assert "auth_candidate" in top_focus.interaction_kinds
    assert "auth_privileged_surface" in top_focus.interaction_kinds


def test_phase10_strategic_planner_prefers_compare_role_access_for_auth_pressure() -> None:
    from app.engine.ai_strategy_advisor import StrategyRecommendation
    from app.engine.planner_target_model_loader import (
        PlannerCapabilityPressureSummary,
        PlannerRouteGroupSummary,
        PlannerTargetModelSummary,
        PlannerTargetProfileHypothesisSummary,
    )
    from app.engine.strategic_planner import StrategicPlanner, StrategicPlannerContext

    planner = StrategicPlanner()
    recommendation = StrategyRecommendation(
        recommended_tools=[{"tool_id": "nuclei", "priority": "low"}],
        attack_vectors=["auth", "idor"],
        endpoint_focus=["https://demo.test/admin/users"],
        phase_decision="proceed",
        strategy_notes="Role differential pressure is strongest on the admin surface.",
        confidence=0.81,
    )
    target_model = PlannerTargetModelSummary(
        route_group_count=1,
        auth_surface_count=3,
        parameter_count=1,
        workflow_edge_count=1,
        source_artifact_types=["endpoints"],
        route_groups=[
            PlannerRouteGroupSummary(
                route_group="/admin/users",
                focus_score=14,
                requires_auth=True,
                auth_variants=["unauthenticated", "user", "admin"],
                parameter_names=["userId"],
                endpoint_urls=["https://demo.test/admin/users"],
                workflow_edge_count=1,
                interaction_kinds=["auth_route_assessment", "auth_candidate", "auth_role_pressure", "auth_privileged_surface"],
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
                    "medium": 1,
                    "low": 0,
                    "info": 0,
                },
                evidence_gaps=["verification"],
            )
        ],
        target_profile_hypotheses=[
            PlannerTargetProfileHypothesisSummary(
                key="auth_heavy_admin_portal",
                confidence=0.84,
                evidence=["privileged route indicators observed", "multiple auth surfaces observed"],
                preferred_capability_pack_keys=["p3a_multi_role_stateful_auth"],
                planner_bias_rules=["prefer differential replay across roles before generic verification"],
                benchmark_target_keys=["repo_demo_api"],
            )
        ],
        capability_pressures=[
            PlannerCapabilityPressureSummary(
                pack_key="p3a_multi_role_stateful_auth",
                pressure_score=67,
                target_profile="auth_heavy_admin_portal",
                target_profile_keys=["auth_heavy_admin_portal", "spa_rest_api"],
                challenge_family_keys=["broken_authentication", "broken_access_control"],
                planner_action_keys=["compare_role_access", "enumerate_privileged_api_surface"],
                proof_contract_keys=["role_differential_access_contract"],
                top_route_groups=["/admin/users"],
                advisory_ready=True,
                advisory_mode="multi_role_auth_route_focus",
                negative_evidence_count=0,
                advisory_artifact_ref="artifacts/test/auth-capability.json",
            )
        ],
        advisory_artifact_refs=[],
    )

    plan = planner.build_plan(
        StrategicPlannerContext(
            scan_id="scan-auth",
            dag_id="dag-auth",
            scan_type="full",
            asset_type="web",
            phase_completed=2,
            current_progress=52,
            template_node_count=4,
            template_tool_ids=["web_interact", "custom_poc", "ffuf", "nuclei"],
            active_phase_tool_ids=["web_interact", "custom_poc", "ffuf", "nuclei"],
            recommendation=recommendation,
            target_model=target_model,
        )
    )

    assert "web_interact" in plan.recommended_tool_ids
    assert "custom_poc" in plan.recommended_tool_ids
    assert any(action.action_type in {"compare_role_access", "enumerate_privileged_api_surface"} for action in plan.actions)
