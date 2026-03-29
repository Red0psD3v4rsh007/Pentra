from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_phase10_capability_registry_loads_disclosure_pack() -> None:
    from app.engine.capabilities.registry import load_capability_registry

    registry = load_capability_registry()

    assert "p3a_disclosure_misconfig_crypto" in registry
    manifest = registry["p3a_disclosure_misconfig_crypto"].manifest
    assert manifest.target_profile_keys == [
        "spa_rest_api",
        "traditional_server_rendered",
        "auth_heavy_admin_portal",
        "upload_parser_heavy",
    ]
    assert set(manifest.knowledge_dependencies.cheatsheet_category_keys) == {
        "disclosure_misconfig_components",
    }
    assert {
        "owasp_http_headers_cheat_sheet",
        "owasp_wstg_configuration_deployment_management",
        "owasp_wstg_error_handling",
        "owasp_wstg_weak_cryptography",
    } <= set(manifest.knowledge_dependencies.source_registry_keys)


def test_phase10_disclosure_pack_generates_stacktrace_component_and_crypto_pressure() -> None:
    from app.engine.capabilities.disclosure_misconfig_crypto import build_disclosure_misconfig_crypto_pack

    pack = build_disclosure_misconfig_crypto_pack(
        base_url="https://demo.test",
        scan_config={"stateful_testing": {"enabled": True}},
        pages=[
            {
                "url": "https://demo.test/internal/debug",
                "route_group": "/internal/debug",
                "status_code": 500,
                "content_type": "text/html",
                "response_preview": "<pre>debug=true\nstacktrace=demo-only\nuid=1000(appuser)</pre>",
                "session_label": "anonymous",
                "auth_state": "none",
                "requires_auth": False,
            },
            {
                "url": "https://demo.test/openapi.json",
                "route_group": "/openapi.json",
                "status_code": 200,
                "content_type": "application/json",
                "response_preview": '{"openapi":"3.0.3","paths":{"/api/v1/users/{id}":{"get":{}}}}',
                "session_label": "anonymous",
                "auth_state": "none",
                "requires_auth": False,
            },
            {
                "url": "https://demo.test/api/v1/public-config",
                "route_group": "/api/v1/public-config",
                "status_code": 200,
                "content_type": "application/json",
                "response_preview": '{"config":{"jwt_secret":"demo-dev-secret","client_secret":"demo-client","algorithm":"HS256"}}',
                "session_label": "anonymous",
                "auth_state": "none",
                "requires_auth": False,
            },
        ],
        forms=[],
        sessions=[],
        replays=[
            {
                "replay_key": "anonymous:GET /openapi.json",
                "target_url": "https://demo.test/openapi.json",
                "session_label": "anonymous",
                "response_preview": '{"openapi":"3.0.3","paths":{"\\/api\\/v1\\/users\\/{id}":{"get":{}}}}',
            }
        ],
        probe_findings=[
            {
                "route_group": "/internal/debug",
                "vulnerability_type": "stack_trace_exposure",
                "description": "Verbose error output exposed internal stacktrace markers.",
            }
        ],
    )

    summary = pack["capability_summary"]
    assert summary["pack_key"] == "p3a_disclosure_misconfig_crypto"
    assert summary["enabled"] is True
    assert summary["target_profile"] == "auth_heavy_admin_portal"
    assert summary["candidate_count"] >= 3
    assert summary["planner_hook_count"] >= 3
    assert summary["ai_advisory_ready"] is True

    states = {item["route_group"]: item["assessment_state"] for item in summary["route_assessments"]}
    assert states["/internal/debug"] == "stack_trace_candidate"
    assert states["/openapi.json"] == "component_truth_candidate"
    assert states["/api/v1/public-config"] == "weak_crypto_candidate"

    candidate_types = {item["vulnerability_type"] for item in pack["candidates"]}
    assert "stack_trace_exposure" in candidate_types
    assert "openapi_exposure" in candidate_types
    assert "credential_exposure" in candidate_types
