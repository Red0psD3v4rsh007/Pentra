from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_phase10_target_model_loader_builds_injection_pressure() -> None:
    from app.engine.planner_target_model_loader import _build_planner_target_model

    artifact_entries = [
        {
            "artifact_type": "endpoints",
            "storage_ref": "artifacts/test/injection-capability.json",
            "payload": {
                "artifact_type": "endpoints",
                "items": [],
                "injection_capability": {
                    "pack_key": "p3a_injection",
                    "target_profile": "graphql_heavy_application",
                    "target_profile_keys": [
                        "spa_rest_api",
                        "traditional_server_rendered",
                        "graphql_heavy_application",
                    ],
                    "benchmark_target_keys": ["repo_demo_api", "webgoat_local"],
                    "challenge_family_keys": ["injection", "input_validation"],
                    "planner_action_keys": ["verify_suspected_injection"],
                    "proof_contract_keys": ["injection_replay_contract"],
                    "candidate_count": 2,
                    "planner_hook_count": 2,
                    "ai_advisory_ready": True,
                    "advisory_context": {
                        "enabled": True,
                        "advisory_mode": "injection_parameter_focus",
                    },
                    "route_assessment_counts": {
                        "injection_candidate": 1,
                        "graphql_candidate": 1,
                        "heuristic_only": 0,
                        "negative_evidence_routes": 0,
                    },
                    "route_assessments": [
                        {
                            "route_group": "/graphql",
                            "page_url": "https://demo.test/graphql",
                            "assessment_state": "graphql_candidate",
                            "risk_score": 79,
                            "advisory_priority": 86,
                            "parameter_hypotheses": ["query", "variables"],
                            "proof_contracts": ["injection_replay_contract"],
                            "session_labels": ["user"],
                            "auth_states": ["authenticated"],
                            "requires_auth": True,
                            "graphql_surface": True,
                            "candidate_vulnerability_types": ["graphql_injection"],
                            "evidence_gaps": ["verification", "request_body_shape"],
                        }
                    ],
                },
                "relationships": [],
            },
        }
    ]

    summary = _build_planner_target_model(findings=[], artifact_entries=artifact_entries)

    assert summary.capability_pressures
    assert summary.capability_pressures[0].pack_key == "p3a_injection"
    assert summary.capability_pressures[0].pressure_score > 0
    assert summary.advisory_artifact_refs[0]["pack_key"] == "p3a_injection"

    top_focus = summary.top_focus
    assert top_focus is not None
    assert top_focus.route_group == "/graphql"
    assert "injection_candidate" in top_focus.interaction_kinds
    assert "graphql_candidate" in top_focus.interaction_kinds
    assert "graphql_injection" in top_focus.vulnerability_types


def test_phase10_strategic_planner_prefers_injection_verification() -> None:
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
        recommended_tools=[{"tool_id": "sqlmap", "priority": "high"}],
        attack_vectors=["sqli", "graphql"],
        endpoint_focus=["https://demo.test/graphql"],
        phase_decision="proceed",
        strategy_notes="Request-shape pressure is strongest on the GraphQL route.",
        confidence=0.78,
    )
    target_model = PlannerTargetModelSummary(
        route_group_count=1,
        auth_surface_count=1,
        parameter_count=2,
        workflow_edge_count=0,
        source_artifact_types=["endpoints"],
        route_groups=[
            PlannerRouteGroupSummary(
                route_group="/graphql",
                focus_score=13,
                requires_auth=True,
                auth_variants=["authenticated"],
                parameter_names=["query", "variables"],
                endpoint_urls=["https://demo.test/graphql"],
                workflow_edge_count=0,
                interaction_kinds=["injection_route_assessment", "injection_candidate", "graphql_candidate", "graphql_surface"],
                safe_replay=True,
                vulnerability_types=["graphql_injection"],
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
                evidence_gaps=["verification", "request_body_shape"],
            )
        ],
        target_profile_hypotheses=[
            PlannerTargetProfileHypothesisSummary(
                key="graphql_heavy_application",
                confidence=0.84,
                evidence=["graphql route observed"],
                preferred_capability_pack_keys=["p3a_injection"],
                planner_bias_rules=["preserve operation names and variable keys during replay"],
                benchmark_target_keys=["repo_demo_api"],
            )
        ],
        capability_pressures=[
            PlannerCapabilityPressureSummary(
                pack_key="p3a_injection",
                pressure_score=72,
                target_profile="graphql_heavy_application",
                target_profile_keys=["graphql_heavy_application", "spa_rest_api"],
                challenge_family_keys=["injection", "input_validation"],
                planner_action_keys=["verify_suspected_injection"],
                proof_contract_keys=["injection_replay_contract"],
                top_route_groups=["/graphql"],
                advisory_ready=True,
                advisory_mode="injection_parameter_focus",
                negative_evidence_count=0,
                advisory_artifact_ref="artifacts/test/injection-capability.json",
            )
        ],
        advisory_artifact_refs=[],
    )

    plan = planner.build_plan(
        StrategicPlannerContext(
            scan_id="scan-injection",
            dag_id="dag-injection",
            scan_type="full",
            asset_type="web",
            phase_completed=2,
            current_progress=61,
            template_node_count=4,
            template_tool_ids=["web_interact", "sqlmap", "ffuf", "nuclei"],
            active_phase_tool_ids=["web_interact", "sqlmap", "ffuf", "nuclei"],
            recommendation=recommendation,
            target_model=target_model,
        )
    )

    assert "sqlmap" in plan.recommended_tool_ids
    assert any(action.action_type == "verify_suspected_injection" for action in plan.actions)
