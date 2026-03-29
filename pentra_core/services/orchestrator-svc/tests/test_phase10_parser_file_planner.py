from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_phase10_target_model_loader_builds_parser_file_pressure() -> None:
    from app.engine.planner_target_model_loader import _build_planner_target_model

    artifact_entries = [
        {
            "artifact_type": "endpoints",
            "storage_ref": "artifacts/test/parser-file-capability.json",
            "payload": {
                "artifact_type": "endpoints",
                "items": [],
                "parser_file_abuse_capability": {
                    "pack_key": "p3a_parser_file_abuse",
                    "target_profile": "upload_parser_heavy",
                    "target_profile_keys": [
                        "upload_parser_heavy",
                        "spa_rest_api",
                        "traditional_server_rendered",
                    ],
                    "benchmark_target_keys": ["repo_parser_upload_demo"],
                    "challenge_family_keys": ["xxe", "insecure_deserialization"],
                    "planner_action_keys": ["probe_parser_boundaries"],
                    "proof_contract_keys": ["xxe_parser_contract", "deserialization_replay_contract"],
                    "candidate_count": 2,
                    "planner_hook_count": 2,
                    "ai_advisory_ready": True,
                    "advisory_context": {
                        "enabled": True,
                        "advisory_mode": "parser_boundary_focus",
                    },
                    "route_assessment_counts": {
                        "xxe_candidate": 1,
                        "deserialization_candidate": 1,
                        "heuristic_only": 0,
                        "negative_evidence_routes": 0,
                    },
                    "route_assessments": [
                        {
                            "route_group": "/portal/import/xml",
                            "page_url": "https://demo.test/portal/import/xml",
                            "assessment_state": "xxe_candidate",
                            "risk_score": 81,
                            "advisory_priority": 89,
                            "parameter_hypotheses": ["xml_document", "import_mode"],
                            "file_field_names": [],
                            "proof_contracts": ["xxe_parser_contract"],
                            "session_labels": ["user"],
                            "auth_states": ["authenticated"],
                            "requires_auth": True,
                            "upload_surface": True,
                            "xml_surface": True,
                            "serialized_surface": False,
                            "candidate_vulnerability_types": ["xxe"],
                            "evidence_gaps": ["verification", "parser_response_delta"],
                        }
                    ],
                },
                "relationships": [],
            },
        }
    ]

    summary = _build_planner_target_model(findings=[], artifact_entries=artifact_entries)

    assert summary.capability_pressures
    assert summary.capability_pressures[0].pack_key == "p3a_parser_file_abuse"
    assert summary.capability_pressures[0].pressure_score > 0
    assert summary.advisory_artifact_refs[0]["pack_key"] == "p3a_parser_file_abuse"

    top_focus = summary.top_focus
    assert top_focus is not None
    assert top_focus.route_group == "/portal/import/xml"
    assert "parser_candidate" in top_focus.interaction_kinds
    assert "xxe_candidate" in top_focus.interaction_kinds
    assert "xxe" in top_focus.vulnerability_types


def test_phase10_strategic_planner_prefers_parser_boundary_probe() -> None:
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
        recommended_tools=[{"tool_id": "web_interact", "priority": "high"}],
        attack_vectors=["xxe", "deserialization"],
        endpoint_focus=["https://demo.test/portal/import/xml"],
        phase_decision="proceed",
        strategy_notes="Parser boundary pressure is strongest on the XML import route.",
        confidence=0.81,
    )
    target_model = PlannerTargetModelSummary(
        route_group_count=1,
        auth_surface_count=1,
        parameter_count=2,
        workflow_edge_count=0,
        source_artifact_types=["endpoints"],
        route_groups=[
            PlannerRouteGroupSummary(
                route_group="/portal/import/xml",
                focus_score=12,
                requires_auth=True,
                auth_variants=["authenticated"],
                parameter_names=["xml_document", "import_mode"],
                endpoint_urls=["https://demo.test/portal/import/xml"],
                workflow_edge_count=0,
                interaction_kinds=[
                    "parser_route_assessment",
                    "parser_candidate",
                    "xxe_candidate",
                    "upload_surface",
                    "xml_parser_surface",
                ],
                safe_replay=True,
                vulnerability_types=["xxe"],
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
                evidence_gaps=["verification", "parser_response_delta"],
            )
        ],
        target_profile_hypotheses=[
            PlannerTargetProfileHypothesisSummary(
                key="upload_parser_heavy",
                confidence=0.82,
                evidence=["upload and parser routes observed"],
                preferred_capability_pack_keys=["p3a_parser_file_abuse"],
                planner_bias_rules=["keep upload workflow context attached to parser replay"],
                benchmark_target_keys=["repo_parser_upload_demo"],
            )
        ],
        capability_pressures=[
            PlannerCapabilityPressureSummary(
                pack_key="p3a_parser_file_abuse",
                pressure_score=71,
                target_profile="upload_parser_heavy",
                target_profile_keys=["upload_parser_heavy", "spa_rest_api"],
                challenge_family_keys=["xxe", "insecure_deserialization"],
                planner_action_keys=["probe_parser_boundaries"],
                proof_contract_keys=["xxe_parser_contract", "deserialization_replay_contract"],
                top_route_groups=["/portal/import/xml"],
                advisory_ready=True,
                advisory_mode="parser_boundary_focus",
                negative_evidence_count=0,
                advisory_artifact_ref="artifacts/test/parser-file-capability.json",
            )
        ],
        advisory_artifact_refs=[],
    )

    plan = planner.build_plan(
        StrategicPlannerContext(
            scan_id="scan-parser",
            dag_id="dag-parser",
            scan_type="full",
            asset_type="web",
            phase_completed=2,
            current_progress=68,
            template_node_count=4,
            template_tool_ids=["web_interact", "custom_poc", "ffuf", "nuclei"],
            active_phase_tool_ids=["web_interact", "custom_poc", "ffuf", "nuclei"],
            recommendation=recommendation,
            target_model=target_model,
        )
    )

    assert "web_interact" in plan.recommended_tool_ids
    assert any(action.action_type == "probe_parser_boundaries" for action in plan.actions)
