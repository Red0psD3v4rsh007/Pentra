from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest


def test_browser_xss_capability_manifest_loads() -> None:
    from app.engine.capabilities.browser_xss import (
        load_browser_xss_capability_manifest,
        load_browser_xss_payload_registry,
    )

    manifest = load_browser_xss_capability_manifest()
    payload_registry = load_browser_xss_payload_registry()

    assert manifest["pack_key"] == "p3a_browser_xss"
    assert "browser_execution_xss" in manifest["proof_contract_keys"]
    assert "stored_execution_xss" in manifest["proof_contract_keys"]
    assert payload_registry["pack_key"] == "p3a_browser_xss"
    assert "query_canary_reflection" in payload_registry["payload_archetypes_by_key"]
    assert "stored_form_canary_replay" in payload_registry["payload_archetypes_by_key"]


def test_browser_xss_capability_builds_structured_spa_candidate() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pack = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={
            "stateful_testing": {
                "xss": {
                    "enabled": True,
                    "route_hints": ["/#/search", "/#/contact"],
                    "max_candidates": 5,
                }
            }
        },
        pages=[
            {
                "url": "http://127.0.0.1:3001/#/search?q=demo",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.search", "urlsearchparams"],
                "route_group": "/#/search",
                "script_signal_count": 2,
            }
        ],
        forms=[],
    )

    assert pack["capability_summary"]["target_profile"] == "spa_rest_api"
    assert pack["capability_summary"]["benchmark_inputs_enabled"] is False
    assert pack["capability_summary"]["candidate_count"] >= 1
    assert pack["capability_summary"]["route_assessment_counts"]["candidate_ready"] >= 1
    assert pack["capability_summary"]["route_assessment_counts"]["route_hint_matches"] >= 1
    route_assessment = next(
        assessment
        for assessment in pack["capability_summary"]["route_assessments"]
        if assessment["route_group"] == "/#/search"
    )
    assert route_assessment["assessment_state"] == "candidate_ready"
    assert route_assessment["next_action"] == "verify_browser_flow"
    assert route_assessment["risk_score"] > 0
    assert route_assessment["route_hint_match"] is True
    candidate = pack["candidates"][0]
    assert candidate["challenge_family"] == "xss"
    assert candidate["attack_primitive"] == "dom_xss_browser_probe"
    assert candidate["workflow_state"] == "client_search_reflection_state"
    assert candidate["planner_action"] == "map_client_side_sinks"
    assert candidate["proof_contract"] == "browser_execution_xss"
    assert candidate["benchmark_route_hint_match"] is True
    assert "route_hint_match" not in candidate["evidence_channels"]
    assert candidate["source"]["kind"] in {"location.search", "urlsearchparams"}
    assert candidate["sink"]["kind"] == "innerHTML"
    assert candidate["payload_archetype_key"] in {"query_canary_reflection", "hash_query_canary_dom"}
    assert candidate["payload_selector"]["selected_key"] == candidate["payload_archetype_key"]
    assert candidate["payload_plan"]["archetype_key"] == candidate["payload_archetype_key"]
    assert candidate["payload_plan"]["transport"] in {"query", "hash_query"}
    assert candidate["verification_context"]["verify_type"] == "xss_browser"
    assert candidate["verification_context"]["payload_plan"]["archetype_key"] == candidate["payload_archetype_key"]


def test_browser_xss_capability_builds_stored_candidate_from_safe_replay_form() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pack = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={"stateful_testing": {"xss": {"enabled": True, "route_hints": ["/#/contact"]}}},
        pages=[
            {
                "url": "http://127.0.0.1:3001/#/contact",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.hash"],
                "route_group": "/#/contact",
                "script_signal_count": 2,
                "requires_auth": False,
                "session_label": "unauthenticated",
                "auth_state": "none",
            }
        ],
        forms=[
            {
                "page_url": "http://127.0.0.1:3001/#/contact",
                "action_url": "http://127.0.0.1:3001/api/Feedbacks/",
                "method": "POST",
                "field_names": ["comment", "rating"],
                "hidden_fields": {"pentra_safe_replay": "true", "csrf_token": "csrf-demo"},
                "safe_replay": True,
                "requires_auth": False,
                "session_label": "unauthenticated",
            }
        ],
    )

    stored = next(candidate for candidate in pack["candidates"] if candidate["attack_primitive"] == "stored_xss_workflow_probe")
    assert pack["capability_summary"]["benchmark_inputs_enabled"] is False
    assert stored["proof_contract"] == "stored_execution_xss"
    assert stored["planner_action"] == "replay_stored_xss_workflow"
    assert stored["payload_archetype_key"] == "stored_form_canary_replay"
    assert stored["payload_selector"]["selected_key"] == "stored_form_canary_replay"
    assert stored["payload_plan"]["transport"] == "stored_form"
    assert stored["benchmark_route_hint_match"] is True
    assert "route_hint_match" not in stored["evidence_channels"]
    assert stored["verification_context"]["flow_mode"] == "stored"
    assert stored["verification_context"]["form_hidden_fields"]["csrf_token"] == "csrf-demo"
    assert stored["verification_context"]["payload_plan"]["archetype_key"] == "stored_form_canary_replay"


def test_browser_xss_capability_builds_stored_candidate_from_workflow_seed() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pack = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={
            "stateful_testing": {
                "xss": {
                    "enabled": True,
                    "benchmark_inputs_enabled": True,
                    "route_hints": ["/#/contact"],
                    "workflow_seeds": [
                        {
                            "page_url": "/#/contact",
                            "route_group": "/#/contact",
                            "action_url": "/api/Feedbacks/",
                            "method": "POST",
                            "field_names": ["comment"],
                            "hidden_fields": {"rating": "5"},
                            "render_url": "/#/about",
                            "safe_replay": True,
                            "sink_markers": ["innerHTML"],
                            "source_markers": ["persistent_form_field"],
                        }
                    ],
                }
            }
        },
        pages=[
            {
                "url": "http://127.0.0.1:3001/main.js",
                "content_type": "application/javascript",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.hash"],
                "script_signal_count": 3,
            }
        ],
        forms=[],
    )

    stored = next(candidate for candidate in pack["candidates"] if candidate["attack_primitive"] == "stored_xss_workflow_probe")
    assert pack["capability_summary"]["benchmark_inputs_enabled"] is True
    assert stored["route_group"] == "/#/contact"
    assert stored["benchmark_route_hint_match"] is True
    assert stored["payload_plan"]["render_url"] == "http://127.0.0.1:3001/#/about"
    assert stored["verification_context"]["render_url"] == "http://127.0.0.1:3001/#/about"
    counts = pack["capability_summary"]["route_assessment_counts"]
    assert counts["candidate_ready"] >= 1
    assert counts["route_hint_matches"] >= 1


def test_browser_xss_capability_reports_negative_route_evidence_for_low_signal_pages() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pack = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={"stateful_testing": {"xss": {"enabled": True, "route_hints": ["/#/contact"]}}},
        pages=[
            {
                "url": "http://127.0.0.1:3001/#/profile",
                "content_type": "text/html",
                "dom_source_markers": ["location.hash"],
                "route_group": "/#/profile",
                "script_signal_count": 1,
            }
        ],
        forms=[],
    )

    assert pack["capability_summary"]["candidate_count"] == 0
    assert pack["capability_summary"]["route_assessment_counts"]["negative_evidence_routes"] == 1
    assessment = pack["capability_summary"]["route_assessments"][0]
    assert assessment["assessment_state"] == "source_only"
    assert assessment["negative_evidence"] is True
    assert assessment["next_action"] == "search_for_dangerous_sink"
    assert assessment["route_hint_match"] is False


def test_browser_xss_capability_synthesizes_route_assessment_for_seeded_hash_candidate() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pack = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={
            "stateful_testing": {
                "xss": {
                    "enabled": True,
                    "benchmark_inputs_enabled": True,
                    "seed_paths": ["/#/search?q=pentra-seed"],
                    "route_hints": ["/#/search"],
                }
            }
        },
        pages=[
            {
                "url": "http://127.0.0.1:3001/main.js",
                "content_type": "application/javascript",
                "source_url": "http://127.0.0.1:3001/",
                "dom_sink_markers": ["innerHTML", "document.write"],
                "dom_source_markers": ["location.hash", "location.search", "decodeURIComponent"],
                "script_signal_count": 5,
            }
        ],
        forms=[],
    )

    counts = pack["capability_summary"]["route_assessment_counts"]
    assert counts["candidate_ready"] >= 1
    assert counts["route_hint_matches"] >= 1
    seeded_assessment = next(
        assessment
        for assessment in pack["capability_summary"]["route_assessments"]
        if assessment["route_group"] == "/#/search"
    )
    assert seeded_assessment["assessment_state"] == "candidate_ready"
    assert seeded_assessment["route_hint_match"] is True
    assert seeded_assessment["next_action"] == "verify_browser_flow"


def test_browser_xss_capability_generates_multiple_safe_vectors_for_real_world_route() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pack = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={
            "stateful_testing": {
                "xss": {
                    "enabled": True,
                    "max_vectors_per_route": 4,
                }
            }
        },
        pages=[
            {
                "url": "http://127.0.0.1:3001/portal/messages",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.search", "urlsearchparams"],
                "route_group": "/portal/messages",
                "script_signal_count": 4,
            }
        ],
        forms=[],
    )

    message_candidates = [
        candidate
        for candidate in pack["candidates"]
        if candidate["route_group"] == "/portal/messages"
    ]
    request_urls = {candidate["request_url"] for candidate in message_candidates}

    assert len(message_candidates) >= 2
    assert any("message=pentra-canary" in url for url in request_urls)
    assert any("q=pentra-canary" in url or "search=pentra-canary" in url for url in request_urls)


def test_browser_xss_capability_keeps_generic_spa_routes_as_pressure_not_candidates() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pack = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={"stateful_testing": {"xss": {"enabled": True}}},
        pages=[
            {
                "url": "http://127.0.0.1:3001/#/403",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML", "document.write"],
                "dom_source_markers": ["location.hash", "location.search", "urlsearchparams"],
                "route_group": "/#/403",
                "script_signal_count": 4,
            }
        ],
        forms=[],
    )

    assert pack["capability_summary"]["candidate_count"] == 0
    assessment = next(
        item
        for item in pack["capability_summary"]["route_assessments"]
        if item["route_group"] == "/#/403"
    )
    assert assessment["assessment_state"] == "sink_and_source_unbound"
    assert assessment["next_action"] == "focus_route_analysis"


def test_browser_xss_capability_uses_route_tokens_not_substring_matches() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pack = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={"stateful_testing": {"xss": {"enabled": True}}},
        pages=[
            {
                "url": "http://127.0.0.1:3001/#/accounting",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.search", "urlsearchparams"],
                "route_group": "/#/accounting",
                "script_signal_count": 4,
            },
            {
                "url": "http://127.0.0.1:3001/#/two-factor-authentication",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.search", "urlsearchparams"],
                "route_group": "/#/two-factor-authentication",
                "script_signal_count": 4,
            },
            {
                "url": "http://127.0.0.1:3001/#/last-login-ip",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.search", "urlsearchparams"],
                "route_group": "/#/last-login-ip",
                "script_signal_count": 4,
            },
        ],
        forms=[],
    )

    route_assessments = {
        item["route_group"]: item
        for item in pack["capability_summary"]["route_assessments"]
    }
    assert route_assessments["/#/accounting"]["assessment_state"] == "sink_and_source_unbound"
    assert route_assessments["/#/two-factor-authentication"]["assessment_state"] == "sink_and_source_unbound"
    assert route_assessments["/#/last-login-ip"]["assessment_state"] == "candidate_ready"


def test_browser_xss_capability_marks_route_public_when_unauthenticated_variant_exists() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pack = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={"stateful_testing": {"xss": {"enabled": True, "route_hints": ["/#/contact"]}}},
        pages=[
            {
                "url": "http://127.0.0.1:3001/#/contact",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.search", "urlsearchparams"],
                "route_group": "/#/contact",
                "script_signal_count": 2,
                "requires_auth": False,
                "session_label": "unauthenticated",
                "auth_state": "none",
            },
            {
                "url": "http://127.0.0.1:3001/#/contact",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.search", "urlsearchparams"],
                "route_group": "/#/contact",
                "script_signal_count": 2,
                "requires_auth": True,
                "session_label": "juice-shop-admin",
                "auth_state": "elevated",
            },
        ],
        forms=[],
    )

    assessment = next(
        item
        for item in pack["capability_summary"]["route_assessments"]
        if item["route_group"] == "/#/contact"
    )
    assert assessment["requires_auth"] is False


def test_browser_xss_capability_prioritizes_route_specific_and_stored_candidates_before_root_noise() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pack = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={
            "stateful_testing": {
                "xss": {
                    "enabled": True,
                    "max_candidates": 2,
                    "benchmark_inputs_enabled": True,
                    "route_hints": ["/#/contact"],
                    "workflow_seeds": [
                        {
                            "page_url": "/#/contact",
                            "route_group": "/#/contact",
                            "action_url": "/api/Feedbacks/",
                            "method": "POST",
                            "field_names": ["comment"],
                            "hidden_fields": {"rating": "5"},
                            "render_url": "/#/about",
                            "safe_replay": True,
                            "sink_markers": ["innerHTML"],
                            "source_markers": ["persistent_form_field"],
                        }
                    ],
                }
            }
        },
        pages=[
            {
                "url": "http://127.0.0.1:3001/",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.search", "location.hash", "urlsearchparams"],
                "route_group": "/",
                "script_signal_count": 5,
            },
            {
                "url": "http://127.0.0.1:3001/#/contact",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.hash"],
                "route_group": "/#/contact",
                "script_signal_count": 3,
            },
        ],
        forms=[],
    )

    assert pack["capability_summary"]["candidate_count"] == 2
    assert any(candidate["proof_contract"] == "stored_execution_xss" for candidate in pack["candidates"])
    assert all(candidate["route_group"] != "/" for candidate in pack["candidates"])


def test_browser_xss_capability_diversifies_candidates_across_route_groups() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pack = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={
            "stateful_testing": {
                "xss": {
                    "enabled": True,
                    "max_candidates": 4,
                    "benchmark_inputs_enabled": True,
                    "route_hints": ["/#/contact", "/#/login", "/#/search"],
                    "workflow_seeds": [
                        {
                            "page_url": "/#/contact",
                            "route_group": "/#/contact",
                            "action_url": "/api/Feedbacks/",
                            "method": "POST",
                            "field_names": ["comment"],
                            "hidden_fields": {"rating": "5"},
                            "render_url": "/#/about",
                            "safe_replay": True,
                            "sink_markers": ["innerHTML"],
                            "source_markers": ["persistent_form_field"],
                        }
                    ],
                }
            }
        },
        pages=[
            {
                "url": "http://127.0.0.1:3001/#/contact",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.hash", "urlsearchparams"],
                "route_group": "/#/contact",
                "script_signal_count": 3,
            },
            {
                "url": "http://127.0.0.1:3001/#/login",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.hash", "urlsearchparams"],
                "route_group": "/#/login",
                "script_signal_count": 3,
            },
            {
                "url": "http://127.0.0.1:3001/#/search",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.hash", "location.search", "urlsearchparams"],
                "route_group": "/#/search",
                "script_signal_count": 3,
            },
        ],
        forms=[],
    )

    route_groups = {candidate["route_group"] for candidate in pack["candidates"]}
    assert "/#/contact" in route_groups
    assert "/#/login" in route_groups
    assert "/#/search" in route_groups


def test_browser_xss_capability_builds_ai_advisory_bundle_for_route_focus() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pack = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={
            "stateful_testing": {
                "xss": {
                    "enabled": True,
                    "route_hints": ["/#/search", "/#/contact"],
                    "ai_focus_route_limit": 3,
                    "benchmark_inputs_enabled": True,
                    "workflow_seeds": [
                        {
                            "page_url": "/#/contact",
                            "route_group": "/#/contact",
                            "action_url": "/api/Feedbacks/",
                            "method": "POST",
                            "field_names": ["comment"],
                            "hidden_fields": {"rating": "5"},
                            "render_url": "/#/about",
                            "safe_replay": True,
                            "sink_markers": ["innerHTML"],
                            "source_markers": ["persistent_form_field"],
                        }
                    ],
                }
            }
        },
        pages=[
            {
                "url": "http://127.0.0.1:3001/#/search",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.search", "urlsearchparams"],
                "route_group": "/#/search",
                "script_signal_count": 4,
            },
            {
                "url": "http://127.0.0.1:3001/#/contact",
                "content_type": "text/html",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.hash"],
                "route_group": "/#/contact",
                "script_signal_count": 3,
            },
        ],
        forms=[],
    )

    summary = pack["capability_summary"]
    assert summary["ai_advisory_ready"] is True
    advisory_bundle = summary["ai_advisory_bundle"]
    assert advisory_bundle["enabled"] is True
    assert advisory_bundle["advisory_mode"] == "browser_xss_route_focus"
    assert advisory_bundle["prompt_contract"]["contract_id"] == "pentra.ai.advisory"
    assert advisory_bundle["prompt_contract"]["task_type"] == "advisory_reasoning"
    assert advisory_bundle["focus_routes"]
    assert advisory_bundle["candidate_preview"]
    assert "Contract ID: pentra.ai.advisory" in advisory_bundle["user_prompt"]
    assert any(route["parameter_hypotheses"] for route in advisory_bundle["focus_routes"])
    assert "verification" in advisory_bundle["evidence_gap_summary"]


def test_browser_xss_capability_keeps_benchmark_hints_out_of_confidence_and_risk_scoring() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pages = [
        {
            "url": "http://127.0.0.1:3001/#/search?q=demo",
            "content_type": "text/html",
            "dom_sink_markers": ["innerHTML"],
            "dom_source_markers": ["location.search", "urlsearchparams"],
            "route_group": "/#/search",
            "script_signal_count": 3,
        }
    ]

    hinted = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={"stateful_testing": {"xss": {"enabled": True, "route_hints": ["/#/search"]}}},
        pages=pages,
        forms=[],
    )
    plain = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={"stateful_testing": {"xss": {"enabled": True}}},
        pages=pages,
        forms=[],
    )

    hinted_candidate = next(item for item in hinted["candidates"] if item["route_group"] == "/#/search")
    plain_candidate = next(item for item in plain["candidates"] if item["route_group"] == "/#/search")
    assert hinted_candidate["benchmark_route_hint_match"] is True
    assert plain_candidate["benchmark_route_hint_match"] is False
    assert hinted_candidate["confidence"] == plain_candidate["confidence"]

    hinted_assessment = next(
        item for item in hinted["capability_summary"]["route_assessments"] if item["route_group"] == "/#/search"
    )
    plain_assessment = next(
        item for item in plain["capability_summary"]["route_assessments"] if item["route_group"] == "/#/search"
    )
    assert hinted_assessment["route_hint_match"] is True
    assert plain_assessment["route_hint_match"] is False
    assert hinted_assessment["risk_score"] == plain_assessment["risk_score"]
    assert hinted_assessment["advisory_priority"] == plain_assessment["advisory_priority"]


def test_browser_xss_capability_marks_shared_script_routes_as_non_local_evidence() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pack = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={"stateful_testing": {"xss": {"enabled": True}}},
        pages=[
            {
                "url": "http://127.0.0.1:3001/#/contact",
                "content_type": "text/x-pentra-script-discovery",
                "route_group": "/#/contact",
                "synthetic_discovery": True,
                "source_url": "http://127.0.0.1:3001/main.js",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.search", "urlsearchparams"],
                "script_signal_count": 3,
            }
        ],
        forms=[],
    )

    candidate = next(item for item in pack["candidates"] if item["route_group"] == "/#/contact")
    assessment = next(
        item for item in pack["capability_summary"]["route_assessments"] if item["route_group"] == "/#/contact"
    )

    assert candidate["route_local_evidence"] is False
    assert "route_local_dom_evidence" not in candidate["evidence_channels"]
    assert assessment["route_local_evidence"] is False
    assert assessment["direct_page_count"] == 0
    assert "route_local_evidence" in assessment["evidence_gaps"]


def test_browser_xss_capability_omits_script_assets_from_route_assessments() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pack = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={"stateful_testing": {"xss": {"enabled": True}}},
        pages=[
            {
                "url": "http://127.0.0.1:3001/main.js",
                "content_type": "application/javascript",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.search"],
                "script_signal_count": 4,
            }
        ],
        forms=[],
    )

    route_groups = {
        item["route_group"]
        for item in pack["capability_summary"]["route_assessments"]
    }
    assert "/main.js" not in route_groups


def test_browser_xss_capability_ignores_workflow_seeds_without_explicit_benchmark_enable() -> None:
    from app.engine.capabilities.browser_xss import build_browser_xss_pack

    pack = build_browser_xss_pack(
        base_url="http://127.0.0.1:3001",
        scan_config={
            "stateful_testing": {
                "xss": {
                    "enabled": True,
                    "workflow_seeds": [
                        {
                            "page_url": "/#/contact",
                            "route_group": "/#/contact",
                            "action_url": "/api/Feedbacks/",
                            "method": "POST",
                            "field_names": ["comment"],
                            "hidden_fields": {"rating": "5"},
                            "render_url": "/#/about",
                            "safe_replay": True,
                            "sink_markers": ["innerHTML"],
                            "source_markers": ["persistent_form_field"],
                        }
                    ],
                }
            }
        },
        pages=[
            {
                "url": "http://127.0.0.1:3001/main.js",
                "content_type": "application/javascript",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.hash"],
                "script_signal_count": 3,
            }
        ],
        forms=[],
    )

    assert pack["capability_summary"]["benchmark_inputs_enabled"] is False
    assert not any(candidate["attack_primitive"] == "stored_xss_workflow_probe" for candidate in pack["candidates"])


def test_browser_xss_verification_feedback_marks_no_observation_routes_as_demoted() -> None:
    from app.engine.capabilities.browser_xss import summarize_browser_xss_verification_feedback

    feedback = summarize_browser_xss_verification_feedback(
        candidates=[
            {
                "candidate_key": "search:q",
                "route_group": "/#/search",
                "proof_contract": "browser_execution_xss",
                "request_url": "http://127.0.0.1:3001/#/search?q=pentra-canary",
                "route_local_evidence": False,
            },
            {
                "candidate_key": "login:q",
                "route_group": "/#/login",
                "proof_contract": "browser_execution_xss",
                "request_url": "http://127.0.0.1:3001/#/login?q=pentra-canary",
                "route_local_evidence": False,
            },
        ],
        verification_outcomes=[
            {
                "route_group": "/#/search",
                "request_url": "http://127.0.0.1:3001/#/search?q=pentra-canary",
                "proof_contract": "browser_execution_xss",
                "verification_state": "verified",
            },
            {
                "route_group": "/#/login",
                "request_url": "http://127.0.0.1:3001/#/login?q=pentra-canary",
                "proof_contract": "browser_execution_xss",
                "verification_state": "no_observation",
            },
        ],
        verified_findings=[
            {
                "route_group": "/#/search",
                "verification_state": "verified",
            }
        ],
    )

    assert feedback["verification_counts"]["verified"] == 1
    assert feedback["verification_counts"]["no_observation"] == 1
    assert feedback["verification_counts"]["demoted"] == 1
    assert feedback["verified_routes"] == ["/#/search"]
    assert feedback["demoted_routes"][0]["route_group"] == "/#/login"
    reviewed = {item["candidate_key"]: item for item in feedback["candidate_reviews"]}
    assert reviewed["search:q"]["demoted"] is False
    assert reviewed["login:q"]["demoted"] is True


def test_browser_xss_canary_observation_summarizes_safe_verified_finding() -> None:
    from app.engine.capabilities.browser_xss import summarize_canary_observations

    findings = summarize_canary_observations(
        request_url="http://127.0.0.1:3001/#/search?q=PENTRA_CANARY_123",
        verification_context={
            "route_group": "/#/search",
            "proof_contract": "browser_execution_xss",
            "planner_action": "map_client_side_sinks",
            "attack_primitive": "dom_xss_browser_probe",
            "workflow_state": "client_search_reflection_state",
            "workflow_stage": "exploitation_ready",
            "target_profile": "spa_rest_api",
            "sink_markers": ["innerHTML"],
            "source_markers": ["location.search"],
            "payload_archetype_key": "query_canary_reflection",
        },
        canary_marker="PENTRA_CANARY_123",
        observations={
            "page_url": "http://127.0.0.1:3001/#/search?q=PENTRA_CANARY_123",
            "sink_hits": [{"sink": "innerHTML", "preview": "PENTRA_CANARY_123"}],
            "dom_mutations": [],
        },
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["vulnerability_type"] == "xss"
    assert finding["verification_state"] == "verified"
    assert finding["proof_contract"] == "browser_execution_xss"
    assert "observed_sink:innerHTML" in finding["references"]
    assert "payload_archetype:query_canary_reflection" in finding["references"]
    assert json.dumps(finding["verification_context"])


def test_browser_xss_verifier_falls_back_to_probe_subprocess_when_playwright_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.engine.capabilities.browser_xss import verifier

    expected = [
        {
            "verification_state": "verified",
            "route_group": "/#/search",
            "proof_contract": "browser_execution_xss",
        }
    ]

    async def _fake_subprocess(payload: dict[str, object]) -> list[dict[str, object]]:
        assert payload["request_url"] == "http://127.0.0.1:3001/#/search?q=pentra-seed"
        return expected

    monkeypatch.delenv("PENTRA_BROWSER_XSS_PROBE_SUBPROCESS", raising=False)
    monkeypatch.setattr(verifier, "_playwright_import_available", lambda: False)
    monkeypatch.setattr(verifier, "_verify_browser_xss_canary_subprocess", _fake_subprocess)

    result = asyncio.run(
        verifier.verify_browser_xss_canary(
            {
                "request_url": "http://127.0.0.1:3001/#/search?q=pentra-seed",
                "verification_context": {"flow_mode": "reflected"},
            }
        )
    )

    assert result == expected


def test_browser_xss_verifier_raises_inside_probe_subprocess_when_playwright_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.engine.capabilities.browser_xss import verifier

    monkeypatch.setenv("PENTRA_BROWSER_XSS_PROBE_SUBPROCESS", "1")
    monkeypatch.setattr(verifier, "_playwright_import_available", lambda: False)

    with pytest.raises(RuntimeError, match="playwright is required"):
        asyncio.run(
            verifier.verify_browser_xss_canary(
                {
                    "request_url": "http://127.0.0.1:3001/#/search?q=pentra-seed",
                    "verification_context": {"flow_mode": "reflected"},
                }
            )
        )


def test_browser_xss_verifier_subprocess_exports_pentra_common_pythonpath(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.engine.capabilities.browser_xss import verifier

    captured: dict[str, object] = {}

    class _FakeProcess:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return b"", b""

    async def _fake_create_subprocess_exec(*args: object, **kwargs: object) -> _FakeProcess:
        env = dict(kwargs.get("env") or {})
        captured["pythonpath"] = env.get("PYTHONPATH")
        argv = list(args)
        output_index = argv.index("--output") + 1
        Path(str(argv[output_index])).write_text("[]")
        return _FakeProcess()

    monkeypatch.setattr(verifier.asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    monkeypatch.delenv("PYTHONPATH", raising=False)

    result = asyncio.run(
        verifier._verify_browser_xss_canary_subprocess(
            {
                "request_url": "http://127.0.0.1:3001/#/search?q=pentra-seed",
                "verification_context": {"flow_mode": "reflected"},
            }
        )
    )

    assert result == []
    pythonpath = str(captured.get("pythonpath") or "")
    assert str(verifier._WORKER_APP_ROOT) in pythonpath
    assert str(verifier._PENTRA_COMMON_ROOT) in pythonpath
