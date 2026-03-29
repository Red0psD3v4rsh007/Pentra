from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_phase10_target_model_loader_builds_access_control_workflow_pressure() -> None:
    from app.engine.planner_target_model_loader import _build_planner_target_model

    artifact_entries = [
        {
            "artifact_type": "endpoints",
            "storage_ref": "artifacts/test/access-workflow-capability.json",
            "payload": {
                "artifact_type": "endpoints",
                "items": [],
                "access_control_workflow_abuse_capability": {
                    "pack_key": "p3a_access_control_workflow_abuse",
                    "target_profile": "workflow_heavy_commerce",
                    "target_profile_keys": [
                        "workflow_heavy_commerce",
                        "auth_heavy_admin_portal",
                        "spa_rest_api",
                    ],
                    "benchmark_target_keys": ["repo_demo_api"],
                    "challenge_family_keys": ["broken_access_control", "business_logic_abuse"],
                    "planner_action_keys": [
                        "compare_role_access",
                        "enumerate_privileged_api_surface",
                        "mutate_business_workflows",
                    ],
                    "proof_contract_keys": [
                        "role_differential_access_contract",
                        "sensitive_data_exposure_replay",
                    ],
                    "candidate_count": 2,
                    "planner_hook_count": 2,
                    "ai_advisory_ready": True,
                    "advisory_context": {
                        "enabled": True,
                        "advisory_mode": "access_control_workflow_focus",
                    },
                    "route_assessment_counts": {
                        "access_control_candidate": 1,
                        "workflow_abuse_candidate": 1,
                        "negative_evidence_routes": 0,
                    },
                    "route_assessments": [
                        {
                            "route_group": "/checkout/confirm",
                            "page_url": "https://demo.test/checkout/confirm",
                            "assessment_state": "workflow_abuse_candidate",
                            "risk_score": 81,
                            "advisory_priority": 89,
                            "parameter_hypotheses": ["orderId"],
                            "proof_contracts": ["role_differential_access_contract", "sensitive_data_exposure_replay"],
                            "session_labels": ["user", "admin"],
                            "auth_states": ["authenticated", "elevated"],
                            "requires_auth": True,
                            "privileged_surface": False,
                            "workflow_signal": True,
                            "candidate_vulnerability_types": ["workflow_bypass"],
                            "evidence_gaps": ["verification", "workflow_sequence_replay"],
                        }
                    ],
                },
                "relationships": [
                    {
                        "edge_type": "workflow",
                        "source_url": "https://demo.test/cart",
                        "target_url": "https://demo.test/checkout",
                    },
                    {
                        "edge_type": "workflow",
                        "source_url": "https://demo.test/checkout",
                        "target_url": "https://demo.test/checkout/confirm",
                    },
                ],
            },
        }
    ]

    summary = _build_planner_target_model(findings=[], artifact_entries=artifact_entries)

    assert summary.capability_pressures
    assert summary.capability_pressures[0].pack_key == "p3a_access_control_workflow_abuse"
    assert summary.capability_pressures[0].pressure_score > 0
    assert summary.target_profile_hypotheses
    assert summary.target_profile_hypotheses[0].key == "workflow_heavy_commerce"
    assert summary.advisory_artifact_refs[0]["pack_key"] == "p3a_access_control_workflow_abuse"

    top_focus = summary.top_focus
    assert top_focus is not None
    assert top_focus.route_group == "/checkout/confirm"
    assert "workflow_abuse_candidate" in top_focus.interaction_kinds
    assert "workflow_bypass" in top_focus.vulnerability_types


def test_phase10_strategic_planner_prefers_workflow_mutation_for_workflow_pressure() -> None:
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
        attack_vectors=["idor", "logic"],
        endpoint_focus=["https://demo.test/checkout/confirm"],
        phase_decision="proceed",
        strategy_notes="Workflow-state pressure is strongest on checkout.",
        confidence=0.79,
    )
    target_model = PlannerTargetModelSummary(
        route_group_count=1,
        auth_surface_count=2,
        parameter_count=1,
        workflow_edge_count=3,
        source_artifact_types=["endpoints"],
        route_groups=[
            PlannerRouteGroupSummary(
                route_group="/checkout/confirm",
                focus_score=16,
                requires_auth=True,
                auth_variants=["user", "admin"],
                parameter_names=["orderId"],
                endpoint_urls=["https://demo.test/checkout/confirm"],
                workflow_edge_count=3,
                interaction_kinds=["access_control_route_assessment", "workflow_abuse_candidate", "workflow_signal"],
                safe_replay=True,
                vulnerability_types=["workflow_bypass"],
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
                evidence_gaps=["verification", "workflow_sequence_replay"],
            )
        ],
        target_profile_hypotheses=[
            PlannerTargetProfileHypothesisSummary(
                key="workflow_heavy_commerce",
                confidence=0.86,
                evidence=["checkout routes observed", "workflow edges observed"],
                preferred_capability_pack_keys=["p3a_access_control_workflow_abuse"],
                planner_bias_rules=["preserve workflow ordering and replay checkpoints"],
                benchmark_target_keys=["repo_demo_api"],
            )
        ],
        capability_pressures=[
            PlannerCapabilityPressureSummary(
                pack_key="p3a_access_control_workflow_abuse",
                pressure_score=74,
                target_profile="workflow_heavy_commerce",
                target_profile_keys=["workflow_heavy_commerce", "spa_rest_api"],
                challenge_family_keys=["broken_access_control", "business_logic_abuse"],
                planner_action_keys=["compare_role_access", "mutate_business_workflows"],
                proof_contract_keys=["role_differential_access_contract", "sensitive_data_exposure_replay"],
                top_route_groups=["/checkout/confirm"],
                advisory_ready=True,
                advisory_mode="access_control_workflow_focus",
                negative_evidence_count=0,
                advisory_artifact_ref="artifacts/test/access-workflow-capability.json",
            )
        ],
        advisory_artifact_refs=[],
    )

    plan = planner.build_plan(
        StrategicPlannerContext(
            scan_id="scan-workflow",
            dag_id="dag-workflow",
            scan_type="full",
            asset_type="web",
            phase_completed=2,
            current_progress=61,
            template_node_count=4,
            template_tool_ids=["web_interact", "custom_poc", "ffuf", "nuclei"],
            active_phase_tool_ids=["web_interact", "custom_poc", "ffuf", "nuclei"],
            recommendation=recommendation,
            target_model=target_model,
        )
    )

    assert "web_interact" in plan.recommended_tool_ids
    assert "custom_poc" in plan.recommended_tool_ids
    assert any(action.action_type == "mutate_business_workflows" for action in plan.actions)
