from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_phase10_access_control_pack_reuses_auth_pack_output() -> None:
    from app.engine.capabilities.registry import execute_capability_packs

    capability_results = execute_capability_packs(
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
                "url": "https://demo.test/api/users/1",
                "route_group": "/api/users/{id}",
                "session_label": "user",
                "auth_state": "authenticated",
                "requires_auth": True,
            },
            {
                "url": "https://demo.test/api/users/1",
                "route_group": "/api/users/{id}",
                "session_label": "admin",
                "auth_state": "elevated",
                "requires_auth": True,
            },
            {
                "url": "https://demo.test/checkout/confirm",
                "route_group": "/checkout/confirm",
                "session_label": "user",
                "auth_state": "authenticated",
                "requires_auth": True,
            },
        ],
        forms=[
            {
                "page_url": "https://demo.test/checkout/confirm",
                "action_url": "https://demo.test/checkout/confirm",
                "route_group": "/checkout/confirm",
                "field_names": ["orderId", "quantity"],
                "hidden_field_names": ["csrf_token"],
                "requires_auth": True,
                "session_label": "user",
                "auth_state": "authenticated",
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
                "workflow_key": "workflow:/cart->/checkout/confirm",
                "source_url": "https://demo.test/cart",
                "target_url": "https://demo.test/checkout/confirm",
                "session_label": "user",
            }
        ],
        replays=[
            {
                "replay_key": "user:GET /checkout/confirm",
                "target_url": "https://demo.test/checkout/confirm",
                "session_label": "user",
            }
        ],
        probe_findings=[
            {
                "route_group": "/api/users/{id}",
                "endpoint": "https://demo.test/api/users/1",
                "vulnerability_type": "idor",
            },
            {
                "route_group": "/checkout/confirm",
                "endpoint": "https://demo.test/checkout/confirm",
                "vulnerability_type": "workflow_bypass",
            },
        ],
    )

    access_pack = capability_results["p3a_access_control_workflow_abuse"]["capability_summary"]
    assert access_pack["enabled"] is True
    assert access_pack["auth_pack_dependency"]["pack_key"] == "p3a_multi_role_stateful_auth"
    assert access_pack["candidate_count"] >= 2
    assert access_pack["ai_advisory_ready"] is True

    route_states = {
        item["route_group"]: item["assessment_state"]
        for item in access_pack["route_assessments"]
    }
    assert route_states["/api/users/{id}"] == "access_control_candidate"
    assert route_states["/checkout/confirm"] == "workflow_abuse_candidate"

    candidates = capability_results["p3a_access_control_workflow_abuse"]["candidates"]
    candidate_types = {item["vulnerability_type"] for item in candidates}
    assert "idor" in candidate_types
    assert "workflow_bypass" in candidate_types
