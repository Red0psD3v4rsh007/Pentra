from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_phase10_capability_registry_loads_parser_file_pack() -> None:
    from app.engine.capabilities.registry import load_capability_registry

    registry = load_capability_registry()

    assert "p3a_parser_file_abuse" in registry
    manifest = registry["p3a_parser_file_abuse"].manifest
    assert manifest.target_profile_keys == [
        "upload_parser_heavy",
        "spa_rest_api",
        "traditional_server_rendered",
    ]
    assert set(manifest.knowledge_dependencies.cheatsheet_category_keys) == {
        "parser_file_and_upload",
    }
    assert {
        "owasp_file_upload_cheat_sheet",
        "owasp_deserialization_cheat_sheet",
        "owasp_xxe_prevention_cheat_sheet",
    } <= set(manifest.knowledge_dependencies.source_registry_keys)


def test_phase10_parser_file_pack_generates_xxe_and_deserialization_pressure() -> None:
    from app.engine.capabilities.parser_file_abuse import build_parser_file_abuse_pack

    pack = build_parser_file_abuse_pack(
        base_url="https://demo.test",
        scan_config={"stateful_testing": {"enabled": True}},
        pages=[
            {
                "url": "https://demo.test/portal/upload",
                "route_group": "/portal/upload",
                "content_type": "text/html",
                "response_preview": "<h1>Upload Preview</h1>",
                "session_label": "user",
                "auth_state": "authenticated",
                "requires_auth": True,
            },
            {
                "url": "https://demo.test/portal/import/xml",
                "route_group": "/portal/import/xml",
                "content_type": "application/json",
                "response_preview": '{"parser_message":"XML parser error near DOCTYPE"}',
                "session_label": "user",
                "auth_state": "authenticated",
                "requires_auth": True,
            },
            {
                "url": "https://demo.test/portal/deserialize",
                "route_group": "/portal/deserialize",
                "content_type": "application/json",
                "response_preview": '{"parser_message":"Unsafe serialized object marker reached the parser boundary"}',
                "session_label": "user",
                "auth_state": "authenticated",
                "requires_auth": True,
            },
        ],
        forms=[
            {
                "page_url": "https://demo.test/portal/upload",
                "action_url": "https://demo.test/portal/upload/preview",
                "route_group": "/portal/upload/preview",
                "method": "POST",
                "enctype": "multipart/form-data",
                "multipart": True,
                "field_names": ["filename", "file_contents", "metadata_xml"],
                "field_type_map": {
                    "filename": "text",
                    "document": "file",
                    "file_contents": "text",
                    "metadata_xml": "text",
                },
                "file_field_names": ["document"],
                "hidden_field_names": ["csrf_token", "pentra_safe_replay"],
                "session_label": "user",
                "auth_state": "authenticated",
                "requires_auth": True,
            },
            {
                "page_url": "https://demo.test/portal/import/xml",
                "action_url": "https://demo.test/portal/import/xml",
                "route_group": "/portal/import/xml",
                "method": "POST",
                "enctype": "application/x-www-form-urlencoded",
                "multipart": False,
                "field_names": ["xml_document", "import_mode"],
                "field_type_map": {"xml_document": "text", "import_mode": "text"},
                "file_field_names": [],
                "hidden_field_names": ["csrf_token", "pentra_safe_replay"],
                "session_label": "user",
                "auth_state": "authenticated",
                "requires_auth": True,
            },
            {
                "page_url": "https://demo.test/portal/deserialize",
                "action_url": "https://demo.test/portal/deserialize",
                "route_group": "/portal/deserialize",
                "method": "POST",
                "enctype": "application/x-www-form-urlencoded",
                "multipart": False,
                "field_names": ["serialized_payload", "encoding"],
                "field_type_map": {"serialized_payload": "text", "encoding": "text"},
                "file_field_names": [],
                "hidden_field_names": ["csrf_token", "pentra_safe_replay"],
                "session_label": "user",
                "auth_state": "authenticated",
                "requires_auth": True,
            },
        ],
        sessions=[
            {
                "session_label": "user",
                "auth_state": "authenticated",
                "role": "user",
                "cookie_names": ["parser_demo_user"],
            }
        ],
        replays=[
            {
                "replay_key": "user:POST /portal/import/xml",
                "target_url": "https://demo.test/portal/import/xml",
                "session_label": "user",
            },
            {
                "replay_key": "user:POST /portal/deserialize",
                "target_url": "https://demo.test/portal/deserialize",
                "session_label": "user",
            },
        ],
        probe_findings=[],
    )

    summary = pack["capability_summary"]
    assert summary["pack_key"] == "p3a_parser_file_abuse"
    assert summary["enabled"] is True
    assert summary["target_profile"] == "upload_parser_heavy"
    assert summary["candidate_count"] >= 2
    assert summary["planner_hook_count"] >= 2
    assert summary["ai_advisory_ready"] is True

    states = {item["route_group"]: item["assessment_state"] for item in summary["route_assessments"]}
    assert states["/portal/import/xml"] == "xxe_candidate"
    assert states["/portal/deserialize"] == "deserialization_candidate"

    candidate_types = {item["vulnerability_type"] for item in pack["candidates"]}
    assert "xxe" in candidate_types
    assert "insecure_deserialization" in candidate_types
