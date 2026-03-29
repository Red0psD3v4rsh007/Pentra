from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_build_planner_target_model_prioritizes_route_groups_with_auth_and_verification_pressure() -> None:
    from app.engine.planner_target_model_loader import _build_planner_target_model

    artifact_entries = [
        {
            "artifact_type": "endpoints",
            "payload": {
                "artifact_type": "endpoints",
                "items": [
                    {
                        "url": "https://demo.test/api/orders/123?expand=items",
                        "requires_auth": True,
                        "auth_variants": ["admin"],
                        "form_field_names": ["orderId"],
                    }
                ],
                "relationships": [],
            },
        }
    ]
    findings = [
        {
            "id": "finding-1",
            "scan_job_id": "job-1",
            "source_type": "scanner",
            "severity": "high",
            "tool_source": "nuclei",
            "vulnerability_type": "idor",
            "is_false_positive": False,
            "evidence": {
                "endpoint": "https://demo.test/api/orders/123?expand=items",
                "classification": {
                    "route_group": "/api/orders/{id}",
                    "verification_state": "suspected",
                    "parameter": "orderId",
                },
                "request": "GET /api/orders/123",
                "references": [{"id": "proof-1", "label": "request"}],
            },
        }
    ]

    summary = _build_planner_target_model(findings=findings, artifact_entries=artifact_entries)

    assert summary.route_group_count == 1
    assert summary.auth_surface_count == 1
    assert summary.parameter_count >= 2
    assert summary.has_meaningful_pressure is True

    top_focus = summary.top_focus
    assert top_focus is not None
    assert top_focus.route_group == "/api/orders/{id}"
    assert top_focus.requires_auth is True
    assert "verification" in top_focus.evidence_gaps
    assert top_focus.truth_counts["suspected"] == 1
    assert "orderId" in top_focus.parameter_names


def test_build_planner_target_model_uses_artifact_pressure_before_findings() -> None:
    from app.engine.planner_target_model_loader import _build_planner_target_model

    artifact_entries = [
        {
            "artifact_type": "endpoints",
            "payload": {
                "artifact_type": "endpoints",
                "items": [
                    {
                        "url": "https://demo.test/",
                        "entity_key": "endpoint:https://demo.test/",
                        "requires_auth": True,
                        "auth_variants": ["admin", "user", "unauthenticated"],
                        "interaction_kind": "page",
                    },
                    {
                        "url": "https://demo.test/login",
                        "entity_key": "endpoint:https://demo.test/login",
                        "requires_auth": True,
                        "auth_variants": ["admin", "user", "unauthenticated"],
                        "interaction_kind": "form",
                        "safe_replay": True,
                        "form_field_names": ["username", "password", "csrf_token"],
                        "hidden_field_names": ["csrf_token"],
                    },
                ],
                "relationships": [
                    {
                        "source_key": "endpoint:https://demo.test/",
                        "target_key": "endpoint:https://demo.test/login",
                        "edge_type": "workflow",
                    }
                ],
            },
        }
    ]

    summary = _build_planner_target_model(findings=[], artifact_entries=artifact_entries)

    top_focus = summary.top_focus
    assert top_focus is not None
    assert summary.has_meaningful_pressure is True
    assert top_focus.route_group == "/login"
    assert top_focus.focus_score > 0
    assert top_focus.requires_auth is True
    assert "password" in top_focus.parameter_names
    assert top_focus.workflow_edge_count == 1
    assert "form" in top_focus.interaction_kinds
    assert top_focus.safe_replay is True


def test_build_planner_target_model_rejects_false_positive_truth_pressure() -> None:
    from app.engine.planner_target_model_loader import _build_planner_target_model

    findings = [
        {
            "id": "finding-1",
            "scan_job_id": None,
            "source_type": "scanner",
            "severity": "medium",
            "tool_source": "nuclei",
            "vulnerability_type": "sql_injection",
            "is_false_positive": True,
            "evidence": {
                "endpoint": "https://demo.test/search?q=test",
                "classification": {
                    "route_group": "/search",
                    "parameter": "q",
                },
                "request": "GET /search?q=test",
            },
        }
    ]

    summary = _build_planner_target_model(findings=findings, artifact_entries=[])

    top_focus = summary.top_focus
    assert top_focus is not None
    assert top_focus.truth_counts["rejected"] == 1
    assert top_focus.focus_score == 0
    assert summary.has_meaningful_pressure is False
    assert "verification" not in top_focus.evidence_gaps


def test_build_planner_target_model_uses_browser_xss_route_assessments_before_findings() -> None:
    from app.engine.planner_target_model_loader import _build_planner_target_model

    artifact_entries = [
        {
            "artifact_type": "endpoints",
            "payload": {
                "artifact_type": "endpoints",
                "items": [],
                "browser_xss_capability": {
                    "route_assessments": [
                        {
                            "route_group": "/#/search",
                            "page_url": "http://127.0.0.1:3001/#/search",
                            "assessment_state": "sink_and_source_unbound",
                            "candidate_count": 0,
                            "candidate_field_names": [],
                            "parameter_hypotheses": ["q", "search"],
                            "proof_contracts": ["browser_execution_xss"],
                            "evidence_gaps": ["input_binding", "route_parameter_selection"],
                            "session_labels": ["unauthenticated"],
                            "auth_states": ["none"],
                            "requires_auth": False,
                        },
                        {
                            "route_group": "/#/contact",
                            "page_url": "http://127.0.0.1:3001/#/contact",
                            "assessment_state": "candidate_ready",
                            "candidate_count": 1,
                            "candidate_field_names": ["comment"],
                            "parameter_hypotheses": ["comment", "message"],
                            "proof_contracts": ["stored_execution_xss"],
                            "evidence_gaps": ["verification"],
                            "session_labels": ["unauthenticated"],
                            "auth_states": ["none"],
                            "requires_auth": False,
                        },
                    ]
                },
                "relationships": [],
            },
        }
    ]

    summary = _build_planner_target_model(findings=[], artifact_entries=artifact_entries)

    top_focus = summary.top_focus
    assert top_focus is not None
    assert summary.has_meaningful_pressure is True
    assert top_focus.route_group == "/#/contact"
    assert "xss_candidate" in top_focus.interaction_kinds
    assert top_focus.safe_replay is True
    assert "comment" in top_focus.parameter_names

    search_group = next(group for group in summary.route_groups if group.route_group == "/#/search")
    assert "xss_route_pressure" in search_group.interaction_kinds
    assert "input_binding" in search_group.evidence_gaps
    assert "route_parameter_selection" in search_group.evidence_gaps
    assert "q" in search_group.parameter_names
