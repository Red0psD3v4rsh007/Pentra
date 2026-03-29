from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_phase10_capability_registry_loads_injection_pack() -> None:
    from app.engine.capabilities.registry import load_capability_registry

    registry = load_capability_registry()

    assert "p3a_injection" in registry
    manifest = registry["p3a_injection"].manifest
    assert manifest.target_profile_keys == [
        "spa_rest_api",
        "traditional_server_rendered",
        "graphql_heavy_application",
    ]
    assert set(manifest.knowledge_dependencies.cheatsheet_category_keys) == {
        "injection_and_query_abuse",
        "graphql_and_api_abuse",
    }
    assert {
        "owasp_sql_injection_prevention_cheat_sheet",
        "owasp_query_parameterization_cheat_sheet",
        "portswigger_graphql_api_vulnerabilities",
    } <= set(manifest.knowledge_dependencies.source_registry_keys)


def test_phase10_injection_pack_generates_sql_and_graphql_pressure() -> None:
    from app.engine.capabilities.injection import build_injection_pack

    pack = build_injection_pack(
        base_url="https://demo.test",
        scan_config={"stateful_testing": {"enabled": True}},
        pages=[
            {
                "url": "https://demo.test/api/products?category=1",
                "route_group": "/api/products",
                "content_type": "application/json",
                "response_preview": '{"items":[]}',
                "session_label": "user",
                "auth_state": "authenticated",
                "requires_auth": True,
            },
            {
                "url": "https://demo.test/graphql",
                "route_group": "/graphql",
                "content_type": "application/json",
                "response_preview": '{"errors":[{"message":"Cannot query field"}]}',
                "session_label": "user",
                "auth_state": "authenticated",
                "requires_auth": True,
            },
        ],
        forms=[
            {
                "page_url": "https://demo.test/search",
                "action_url": "https://demo.test/api/products",
                "route_group": "/api/products",
                "method": "GET",
                "field_names": ["category", "sort", "q"],
                "hidden_field_names": [],
                "session_label": "user",
                "auth_state": "authenticated",
                "requires_auth": True,
            }
        ],
        sessions=[
            {
                "session_label": "user",
                "auth_state": "authenticated",
                "role": "user",
                "cookie_names": ["session"],
            }
        ],
        replays=[
            {
                "replay_key": "user:GET /api/products?category=1",
                "target_url": "https://demo.test/api/products?category=1",
                "session_label": "user",
            },
            {
                "replay_key": "user:POST /graphql",
                "target_url": "https://demo.test/graphql",
                "session_label": "user",
            },
        ],
        probe_findings=[
            {
                "route_group": "/api/products",
                "endpoint": "https://demo.test/api/products?category=1",
                "vulnerability_type": "sql_injection",
                "response": "You have an error in your SQL syntax",
            }
        ],
    )

    summary = pack["capability_summary"]
    assert summary["pack_key"] == "p3a_injection"
    assert summary["enabled"] is True
    assert summary["candidate_count"] >= 2
    assert summary["planner_hook_count"] >= 2
    assert summary["ai_advisory_ready"] is True

    states = {item["route_group"]: item["assessment_state"] for item in summary["route_assessments"]}
    assert states["/api/products"] == "injection_candidate"
    assert states["/graphql"] == "graphql_candidate"

    candidate_types = {item["vulnerability_type"] for item in pack["candidates"]}
    assert "sql_injection" in candidate_types
    assert "graphql_injection" in candidate_types

    graphql_route = next(item for item in summary["route_assessments"] if item["route_group"] == "/graphql")
    assert graphql_route["request_template_available"] is True
    assert graphql_route["request_template"]["method"] == "POST"
    assert graphql_route["graphql_introspection_exposed"] is False


def test_phase10_injection_pack_promotes_graphql_introspection_without_existing_replay() -> None:
    from app.engine.capabilities.injection import build_injection_pack

    pack = build_injection_pack(
        base_url="https://demo.test",
        scan_config={"stateful_testing": {"enabled": True}},
        pages=[
            {
                "url": "https://demo.test/graphql",
                "route_group": "/graphql",
                "content_type": "application/json",
                "response_preview": '{"data":{"__schema":{"types":[{"name":"Query"}]}}}',
                "session_label": "user",
                "auth_state": "authenticated",
                "requires_auth": True,
            },
            {
                "url": "https://demo.test/openapi.json",
                "route_group": "/openapi.json",
                "content_type": "application/json",
                "response_preview": '{"paths":{"/graphql":{"post":{"summary":"GraphQL endpoint"}}}}',
                "session_label": "user",
                "auth_state": "authenticated",
                "requires_auth": True,
            },
        ],
        forms=[],
        sessions=[
            {
                "session_label": "user",
                "auth_state": "authenticated",
                "role": "user",
                "cookie_names": ["session"],
            }
        ],
        replays=[],
        probe_findings=[],
    )

    summary = pack["capability_summary"]
    states = {item["route_group"]: item["assessment_state"] for item in summary["route_assessments"]}
    assert states["/graphql"] == "graphql_candidate"
    assert states["/openapi.json"] == "heuristic_only"

    graphql_route = next(item for item in summary["route_assessments"] if item["route_group"] == "/graphql")
    assert graphql_route["graphql_introspection_exposed"] is True
    assert graphql_route["request_template_available"] is True
    assert "request_body_shape" not in graphql_route["evidence_gaps"]

    candidate_types = {
        item["vulnerability_type"]
        for item in pack["candidates"]
        if item["route_group"] == "/graphql"
    }
    assert "graphql_introspection" in candidate_types
