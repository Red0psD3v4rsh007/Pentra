from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from types import SimpleNamespace


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def _scan() -> SimpleNamespace:
    return SimpleNamespace(
        id="11111111-1111-1111-1111-111111111111",
        tenant_id="22222222-2222-2222-2222-222222222222",
        asset_id="33333333-3333-3333-3333-333333333333",
        asset=SimpleNamespace(
            name="Demo API",
            target="https://example.test",
        ),
    )


def _finding(
    *,
    finding_id: str,
    endpoint: str,
    route_group: str,
    vulnerability_type: str,
    truth_state: str,
    severity: str = "high",
    technology: str | None = None,
) -> SimpleNamespace:
    classification = {
        "route_group": route_group,
        "surface": "api",
    }
    if technology:
        classification["primary_technology"] = technology

    return SimpleNamespace(
        id=finding_id,
        severity=severity,
        vulnerability_type=vulnerability_type,
        truth_state=truth_state,
        source_type="exploit_verify" if truth_state == "verified" else "scanner",
        evidence={
            "endpoint": endpoint,
            "target": endpoint,
            "classification": classification,
        },
    )


def test_build_target_model_snapshot_aggregates_routes_auth_workflows_and_parameters():
    from app.services.target_model_service import _build_target_model_snapshot

    artifact_entries = [
        {
            "artifact_type": "endpoints",
            "created_at": datetime(2026, 3, 23, 9, 0, tzinfo=timezone.utc),
            "payload": {
                "artifact_type": "endpoints",
                "items": [
                    {
                        "url": "https://example.test/api/login",
                        "route_group": "/api/login",
                        "surface": "api",
                        "http_method": "POST",
                        "form_field_names": ["email", "password"],
                        "has_csrf": True,
                        "safe_replay": True,
                        "tech_stack": ["Next.js", "FastAPI"],
                        "entity_key": "endpoint:login",
                    },
                    {
                        "url": "https://example.test/api/users/42",
                        "route_group": "/api/users/{id}",
                        "surface": "api",
                        "http_method": "GET",
                        "requires_auth": True,
                        "auth_variants": ["admin"],
                        "tech_stack": ["FastAPI"],
                        "entity_key": "endpoint:users",
                    },
                ],
                "relationships": [
                    {
                        "source_key": "endpoint:login",
                        "target_key": "endpoint:users",
                        "edge_type": "workflow",
                    }
                ],
            },
        }
    ]

    findings = [
        _finding(
            finding_id="finding-1",
            endpoint="https://example.test/api/users/42",
            route_group="/api/users/{id}",
            vulnerability_type="idor",
            truth_state="verified",
            technology="FastAPI",
        )
    ]

    snapshot = _build_target_model_snapshot(
        scan=_scan(),
        findings=findings,
        artifact_entries=artifact_entries,
    )

    assert snapshot["overview"]["endpoint_count"] == 2
    assert snapshot["overview"]["authenticated_endpoint_count"] == 1
    assert snapshot["overview"]["workflow_edge_count"] == 1
    assert snapshot["overview"]["technology_count"] >= 2

    users_group = next(
        item for item in snapshot["route_groups"] if item["route_group"] == "/api/users/{id}"
    )
    assert users_group["requires_auth"] is True
    assert users_group["finding_count"] == 1
    assert users_group["truth_counts"]["verified"] == 1
    assert "idor" in users_group["vulnerability_types"]

    admin_surface = next(item for item in snapshot["auth_surfaces"] if item["label"] == "admin")
    assert admin_surface["endpoint_count"] == 1
    assert "/api/users/{id}" in admin_surface["route_groups"]

    parameter_names = {item["name"] for item in snapshot["parameters"]}
    assert {"email", "password"} <= parameter_names
    password_parameter = next(item for item in snapshot["parameters"] if item["name"] == "password")
    assert password_parameter["likely_sensitive"] is True

    assert snapshot["workflows"][0]["source_route_group"] == "/api/login"
    assert snapshot["workflows"][0]["target_route_group"] == "/api/users/{id}"

    assert snapshot["planner_focus"][0]["route_group"] == "/api/users/{id}"


def test_build_target_model_snapshot_creates_fallback_endpoint_from_finding_only_context():
    from app.services.target_model_service import _build_target_model_snapshot

    findings = [
        _finding(
            finding_id="finding-graphql",
            endpoint="https://example.test/graphql?operationName=ListUsers",
            route_group="/graphql",
            vulnerability_type="graphql_introspection",
            truth_state="suspected",
            technology="GraphQL",
            severity="medium",
        )
    ]

    snapshot = _build_target_model_snapshot(
        scan=_scan(),
        findings=findings,
        artifact_entries=[],
    )

    assert snapshot["overview"]["endpoint_count"] == 1
    assert snapshot["overview"]["source_artifact_types"] == []
    assert snapshot["route_groups"][0]["route_group"] == "/graphql"
    assert snapshot["route_groups"][0]["truth_counts"]["suspected"] == 1

    operation_name = next(item for item in snapshot["parameters"] if item["name"] == "operationName")
    assert operation_name["endpoint_count"] == 1
    assert "/graphql" in operation_name["route_groups"]

    graphql_tech = next(item for item in snapshot["technologies"] if item["technology"] == "GraphQL")
    assert "/graphql" in graphql_tech["route_groups"]


def test_build_target_model_snapshot_normalizes_dynamic_routes_and_ignores_discovery_edges():
    from app.services.target_model_service import _build_target_model_snapshot

    artifact_entries = [
        {
            "artifact_type": "endpoints",
            "created_at": datetime(2026, 3, 23, 10, 0, tzinfo=timezone.utc),
            "payload": {
                "artifact_type": "endpoints",
                "items": [
                    {
                        "url": "https://example.test/orders/123?expand=items",
                        "http_method": "GET",
                        "requires_auth": True,
                        "auth_variants": ["operator"],
                        "hidden_field_names": ["csrf_token"],
                        "entity_key": "endpoint:order-1",
                    },
                    {
                        "url": "https://example.test/orders/456?expand=details",
                        "http_method": "POST",
                        "requires_auth": True,
                        "auth_variants": ["operator"],
                        "entity_key": "endpoint:order-2",
                    },
                ],
                "relationships": [
                    {
                        "source_key": "endpoint:order-1",
                        "target_key": "endpoint:order-2",
                        "edge_type": "discovery",
                    }
                ],
            },
        }
    ]

    snapshot = _build_target_model_snapshot(
        scan=_scan(),
        findings=[],
        artifact_entries=artifact_entries,
    )

    assert snapshot["overview"]["endpoint_count"] == 2
    assert snapshot["overview"]["route_group_count"] == 1
    assert snapshot["overview"]["workflow_edge_count"] == 0

    route_group = snapshot["route_groups"][0]
    assert route_group["route_group"] == "/orders/{id}"
    assert route_group["endpoint_count"] == 2
    assert route_group["requires_auth"] is True
    assert route_group["methods"] == ["GET", "POST"]

    auth_surface = next(item for item in snapshot["auth_surfaces"] if item["label"] == "operator")
    assert auth_surface["endpoint_count"] == 2
    assert auth_surface["route_groups"] == ["/orders/{id}"]

    expand_parameter = next(item for item in snapshot["parameters"] if item["name"] == "expand")
    assert expand_parameter["endpoint_count"] == 2
    assert expand_parameter["locations"] == ["query_or_form"]

    csrf_parameter = next(item for item in snapshot["parameters"] if item["name"] == "csrf_token")
    assert csrf_parameter["likely_sensitive"] is True
    assert "hidden_form" in csrf_parameter["locations"]
