from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_phase10_capability_registry_loads_browser_xss_and_auth_pack() -> None:
    from app.engine.capabilities.registry import load_capability_registry

    registry = load_capability_registry()

    assert {
        "p3a_browser_xss",
        "p3a_multi_role_stateful_auth",
        "p3a_access_control_workflow_abuse",
    } <= set(registry.keys())
    assert registry["p3a_multi_role_stateful_auth"].manifest.target_profile_keys == [
        "auth_heavy_admin_portal",
        "spa_rest_api",
        "workflow_heavy_commerce",
    ]


def test_phase10_multi_role_stateful_auth_pack_generates_role_pressure() -> None:
    from app.engine.capabilities.multi_role_stateful_auth import build_multi_role_stateful_auth_pack

    pack = build_multi_role_stateful_auth_pack(
        base_url="https://demo.test",
        scan_config={
            "stateful_testing": {
                "enabled": True,
                "auth": {
                    "credentials": [
                        {"label": "user", "username": "user", "password": "test", "role": "user"},
                        {"label": "admin", "username": "admin", "password": "admin123", "role": "admin"},
                    ]
                },
            }
        },
        pages=[
            {
                "url": "https://demo.test/login",
                "route_group": "/login",
                "session_label": "unauthenticated",
                "auth_state": "none",
                "requires_auth": False,
            },
            {
                "url": "https://demo.test/admin/users",
                "route_group": "/admin/users",
                "session_label": "admin",
                "auth_state": "elevated",
                "requires_auth": True,
            },
            {
                "url": "https://demo.test/admin/users",
                "route_group": "/admin/users",
                "session_label": "user",
                "auth_state": "authenticated",
                "requires_auth": True,
            },
        ],
        forms=[
            {
                "page_url": "https://demo.test/login",
                "action_url": "https://demo.test/login",
                "route_group": "/login",
                "field_names": ["username", "password"],
                "hidden_field_names": ["csrf_token"],
                "requires_auth": False,
                "session_label": "unauthenticated",
                "auth_state": "none",
            }
        ],
        sessions=[
            {
                "session_label": "unauthenticated",
                "auth_state": "none",
                "role": "anonymous",
                "cookie_names": [],
            },
            {
                "session_label": "user",
                "auth_state": "authenticated",
                "role": "user",
                "cookie_names": ["session"],
            },
            {
                "session_label": "admin",
                "auth_state": "elevated",
                "role": "admin",
                "cookie_names": ["session"],
            },
        ],
        workflows=[
            {
                "workflow_key": "workflow:/login->/admin/users",
                "source_url": "https://demo.test/login",
                "target_url": "https://demo.test/admin/users",
                "session_label": "admin",
            }
        ],
        replays=[
            {
                "replay_key": "admin:GET /admin/users",
                "target_url": "https://demo.test/admin/users",
                "session_label": "admin",
            }
        ],
        probe_findings=[
            {
                "route_group": "/admin/users",
                "endpoint": "https://demo.test/admin/users",
                "vulnerability_type": "privilege_escalation",
            }
        ],
    )

    summary = pack["capability_summary"]
    assert summary["pack_key"] == "p3a_multi_role_stateful_auth"
    assert summary["enabled"] is True
    assert summary["target_profile"] == "auth_heavy_admin_portal"
    assert summary["candidate_count"] >= 1
    assert summary["planner_hook_count"] >= 1
    assert summary["ai_advisory_ready"] is True

    top_route = summary["route_assessments"][0]
    assert top_route["route_group"] == "/admin/users"
    assert top_route["assessment_state"] == "role_differential_candidate"
    assert top_route["planner_action"] in {"compare_role_access", "enumerate_privileged_api_surface"}

    auth_candidate = pack["candidates"][0]
    assert auth_candidate["capability_pack"] == "p3a_multi_role_stateful_auth"
    assert auth_candidate["proof_contract"] == "role_differential_access_contract"
