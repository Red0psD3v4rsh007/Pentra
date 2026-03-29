from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_phase10_target_model_loader_populates_graph_alignment_for_capability_pressure() -> None:
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
                    "target_profile_keys": ["auth_heavy_admin_portal", "spa_rest_api"],
                    "benchmark_target_keys": ["repo_demo_api"],
                    "challenge_family_keys": ["broken_authentication", "broken_access_control"],
                    "attack_primitive_keys": ["idor_role_diff_probe", "session_and_token_abuse_probe"],
                    "planner_action_keys": ["compare_role_access", "pressure_auth_tokens_and_login_flows"],
                    "proof_contract_keys": ["role_differential_access_contract"],
                    "candidate_count": 1,
                    "planner_hook_count": 1,
                    "ai_advisory_ready": True,
                    "advisory_context": {"enabled": True, "advisory_mode": "multi_role_auth_route_focus"},
                    "route_assessment_counts": {
                        "role_differential_candidate": 1,
                        "negative_evidence_routes": 0,
                    },
                    "route_assessments": [
                        {
                            "route_group": "/admin/users",
                            "page_url": "https://demo.test/admin/users",
                            "assessment_state": "role_differential_candidate",
                            "risk_score": 80,
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

    pressure = summary.capability_pressures[0]
    assert pressure.graph_keys
    assert "auth_heavy_admin_portal" in pressure.graph_target_profile_keys
    assert "compare_role_access" in pressure.graph_planner_action_keys
    assert "role_differential_access_contract" in pressure.graph_proof_contract_keys
    assert pressure.graph_rationale


def test_phase10_graph_alignment_prefers_target_profile_specific_graphs() -> None:
    from app.knowledge.ontology_registry import align_capability_graphs

    alignments = align_capability_graphs(
        target_profile_keys=["workflow_heavy_commerce"],
        challenge_family_keys=["business_logic_abuse", "broken_access_control"],
        attack_primitive_keys=["business_workflow_mutation_probe", "idor_role_diff_probe"],
        proof_contract_keys=["role_differential_access_contract", "stored_execution_xss"],
        planner_action_keys=["mutate_business_workflows", "compare_role_access"],
        benchmark_target_keys=["repo_demo_api"],
    )

    assert alignments
    assert alignments[0].graph_key == "workflow_heavy_commerce_capability_graph"
    assert "workflow_heavy_commerce" in alignments[0].matched_target_profile_keys
    assert "mutate_business_workflows" in alignments[0].matched_planner_action_keys


def test_phase10_strategic_planner_includes_graph_alignment_in_rationale() -> None:
    from app.engine.ai_strategy_advisor import StrategyRecommendation
    from app.engine.planner_target_model_loader import (
        PlannerCapabilityPressureSummary,
        PlannerRouteGroupSummary,
        PlannerTargetModelSummary,
        PlannerTargetProfileHypothesisSummary,
    )
    from app.engine.strategic_planner import StrategicPlanner, StrategicPlannerContext

    planner = StrategicPlanner()
    target_model = PlannerTargetModelSummary(
        route_group_count=1,
        auth_surface_count=3,
        parameter_count=1,
        workflow_edge_count=1,
        source_artifact_types=["endpoints"],
        route_groups=[
            PlannerRouteGroupSummary(
                route_group="/admin/users",
                focus_score=15,
                requires_auth=True,
                auth_variants=["unauthenticated", "user", "admin"],
                parameter_names=["userId"],
                endpoint_urls=["https://demo.test/admin/users"],
                workflow_edge_count=1,
                interaction_kinds=["auth_route_assessment", "auth_candidate", "auth_privileged_surface"],
                safe_replay=True,
                vulnerability_types=[],
                truth_counts={key: 0 for key in ["observed", "suspected", "reproduced", "verified", "rejected", "expired"]},
                severity_counts={key: 0 for key in ["critical", "high", "medium", "low", "info"]} | {"medium": 1},
                evidence_gaps=["verification"],
            )
        ],
        target_profile_hypotheses=[
            PlannerTargetProfileHypothesisSummary(
                key="auth_heavy_admin_portal",
                confidence=0.84,
                evidence=["privileged route indicators observed"],
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
                graph_keys=["juice_shop_local_web_graph"],
                graph_planner_action_keys=["compare_role_access"],
                graph_proof_contract_keys=["role_differential_access_contract"],
                graph_rationale=["challenge-family overlap with juice_shop_local_web_graph: broken_access_control"],
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
            recommendation=StrategyRecommendation(
                recommended_tools=[],
                attack_vectors=["auth"],
                endpoint_focus=["https://demo.test/admin/users"],
                phase_decision="proceed",
                strategy_notes="",
                confidence=0.8,
            ),
            target_model=target_model,
        )
    )

    assert plan.actions
    assert "Graph alignment:" in plan.actions[0].rationale
