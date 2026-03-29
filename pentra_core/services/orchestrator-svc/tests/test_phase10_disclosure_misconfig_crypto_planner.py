from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_phase10_target_model_loader_builds_disclosure_pressure() -> None:
    from app.engine.planner_target_model_loader import _build_planner_target_model

    artifact_entries = [
        {
            "artifact_type": "endpoints",
            "storage_ref": "artifacts/test/disclosure-capability.json",
            "payload": {
                "artifact_type": "endpoints",
                "items": [],
                "disclosure_misconfig_crypto_capability": {
                    "pack_key": "p3a_disclosure_misconfig_crypto",
                    "target_profile": "spa_rest_api",
                    "target_profile_keys": [
                        "spa_rest_api",
                        "traditional_server_rendered",
                        "auth_heavy_admin_portal",
                    ],
                    "benchmark_target_keys": ["repo_demo_api"],
                    "challenge_family_keys": [
                        "sensitive_data_exposure",
                        "security_misconfiguration",
                        "vulnerable_components",
                    ],
                    "planner_action_keys": [
                        "inspect_error_and_log_disclosure",
                        "inspect_config_and_secret_exposure",
                        "fingerprint_components_and_hidden_assets",
                    ],
                    "proof_contract_keys": [
                        "stack_trace_disclosure_contract",
                        "component_truth_contract",
                        "misconfiguration_surface_contract",
                    ],
                    "candidate_count": 2,
                    "planner_hook_count": 2,
                    "ai_advisory_ready": True,
                    "advisory_context": {
                        "enabled": True,
                        "advisory_mode": "disclosure_truth_focus",
                    },
                    "route_assessment_counts": {
                        "stack_trace_candidate": 1,
                        "component_truth_candidate": 1,
                        "heuristic_only": 0,
                        "negative_evidence_routes": 0,
                    },
                    "route_assessments": [
                        {
                            "route_group": "/internal/debug",
                            "page_url": "https://demo.test/internal/debug",
                            "assessment_state": "stack_trace_candidate",
                            "risk_score": 92,
                            "advisory_priority": 96,
                            "parameter_hypotheses": [],
                            "proof_contracts": ["stack_trace_disclosure_contract"],
                            "session_labels": ["anonymous"],
                            "auth_states": ["none"],
                            "requires_auth": False,
                            "public_surface": True,
                            "debug_surface": True,
                            "component_surface": False,
                            "config_surface": True,
                            "secret_surface": False,
                            "crypto_surface": False,
                            "candidate_vulnerability_types": ["stack_trace_exposure"],
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
    assert summary.capability_pressures[0].pack_key == "p3a_disclosure_misconfig_crypto"
    assert summary.capability_pressures[0].pressure_score > 0
    assert summary.advisory_artifact_refs[0]["pack_key"] == "p3a_disclosure_misconfig_crypto"

    top_focus = summary.top_focus
    assert top_focus is not None
    assert top_focus.route_group == "/internal/debug"
    assert "disclosure_candidate" in top_focus.interaction_kinds
    assert "stack_trace_candidate" in top_focus.interaction_kinds
    assert "stack_trace_exposure" in top_focus.vulnerability_types


def test_phase10_strategic_planner_prefers_error_disclosure_followup() -> None:
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
        recommended_tools=[
            {"tool_id": "web_interact", "priority": "high"},
            {"tool_id": "httpx_probe", "priority": "medium"},
            {"tool_id": "custom_poc", "priority": "medium"},
        ],
        attack_vectors=["stack_trace_exposure", "openapi_exposure"],
        endpoint_focus=["https://demo.test/internal/debug"],
        phase_decision="proceed",
        strategy_notes="Disclosure pressure is strongest on the debug route.",
        confidence=0.82,
    )
    target_model = PlannerTargetModelSummary(
        route_group_count=1,
        auth_surface_count=0,
        parameter_count=0,
        workflow_edge_count=0,
        source_artifact_types=["endpoints"],
        route_groups=[
            PlannerRouteGroupSummary(
                route_group="/internal/debug",
                focus_score=13,
                requires_auth=False,
                auth_variants=["none"],
                parameter_names=[],
                endpoint_urls=["https://demo.test/internal/debug"],
                workflow_edge_count=0,
                interaction_kinds=[
                    "disclosure_route_assessment",
                    "disclosure_candidate",
                    "stack_trace_candidate",
                    "debug_surface",
                ],
                safe_replay=True,
                vulnerability_types=["stack_trace_exposure"],
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
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
                evidence_gaps=["verification"],
            )
        ],
        target_profile_hypotheses=[
            PlannerTargetProfileHypothesisSummary(
                key="spa_rest_api",
                confidence=0.81,
                evidence=["api and docs routes observed"],
                preferred_capability_pack_keys=["p3a_disclosure_misconfig_crypto", "p3a_injection"],
                planner_bias_rules=["prefer exact route truth over generic route-name guesses"],
                benchmark_target_keys=["repo_demo_api"],
            )
        ],
        capability_pressures=[
            PlannerCapabilityPressureSummary(
                pack_key="p3a_disclosure_misconfig_crypto",
                pressure_score=74,
                target_profile="spa_rest_api",
                target_profile_keys=["spa_rest_api", "auth_heavy_admin_portal"],
                challenge_family_keys=["sensitive_data_exposure", "security_misconfiguration"],
                planner_action_keys=[
                    "inspect_error_and_log_disclosure",
                    "inspect_config_and_secret_exposure",
                    "fingerprint_components_and_hidden_assets",
                ],
                proof_contract_keys=["stack_trace_disclosure_contract", "component_truth_contract"],
                top_route_groups=["/internal/debug"],
                advisory_ready=True,
                advisory_mode="disclosure_truth_focus",
                negative_evidence_count=0,
                advisory_artifact_ref="artifacts/test/disclosure-capability.json",
            )
        ],
        advisory_artifact_refs=[],
    )

    plan = planner.build_plan(
        StrategicPlannerContext(
            scan_id="scan-disclosure",
            dag_id="dag-disclosure",
            scan_type="full",
            asset_type="web",
            phase_completed=2,
            current_progress=74,
            template_node_count=4,
            template_tool_ids=["web_interact", "httpx_probe", "custom_poc", "nuclei"],
            active_phase_tool_ids=["web_interact", "httpx_probe", "custom_poc", "nuclei"],
            recommendation=recommendation,
            target_model=target_model,
        )
    )

    assert "web_interact" in plan.recommended_tool_ids
    assert any(action.action_type == "inspect_error_and_log_disclosure" for action in plan.actions)
