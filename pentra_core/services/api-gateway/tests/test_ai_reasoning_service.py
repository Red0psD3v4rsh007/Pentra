from __future__ import annotations

import os
import sys
from types import SimpleNamespace


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def _sample_context() -> dict:
    return {
        "scan": {
            "scan_id": "scan-1",
            "asset_target": "http://127.0.0.1:8088",
        },
        "report": {
            "executive_summary": "Autonomous assessment found 2 persisted findings.",
            "severity_counts": {
                "critical": 1,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "verification_counts": {
                "verified": 1,
                "suspected": 1,
                "detected": 0,
            },
        },
        "graph": {
            "node_count": 7,
            "edge_count": 11,
            "path_summary": {
                "targets_reached": ["database_access"],
            },
        },
        "findings": [
            {
                "finding_id": "finding-1",
                "title": "Verified database access via SQL injection",
                "severity": "critical",
                "confidence": 97,
                "verification_state": "verified",
                "verification_confidence": 97,
                "exploitability": "high",
                "target": "http://127.0.0.1:8088/api/v1/auth/login",
                "remediation": "Use parameterized queries.",
            },
            {
                "finding_id": "finding-2",
                "title": "Broken Access Control - IDOR",
                "severity": "high",
                "confidence": 91,
                "verification_state": "suspected",
                "verification_confidence": 91,
                "exploitability": "high",
                "target": "http://127.0.0.1:8088/api/v1/users/2",
                "remediation": "Enforce object-level authorization.",
            },
        ],
        "evidence": [],
    }


def test_extract_json_payload_handles_fenced_response():
    from app.services.ai_reasoning_service import _extract_json_payload

    payload = _extract_json_payload(
        """```json
        {"attack_graph": {"summary": "ok"}, "report": {"draft_summary": "ok"}, "findings": []}
        ```"""
    )

    assert payload["attack_graph"]["summary"] == "ok"
    assert payload["report"]["draft_summary"] == "ok"


def test_build_fallback_advisory_marks_verified_finding_immediate():
    from app.services.ai_reasoning_service import _build_fallback_advisory

    advisory = _build_fallback_advisory(_sample_context())

    assert advisory["attack_graph"]["next_steps"]
    assert advisory["report"]["remediation_focus"]
    assert advisory["findings"][0]["triage_priority"] == "immediate"
    assert "verified" in advisory["findings"][0]["exploitability_assessment"]


def test_normalize_reasoning_output_matches_findings_by_title():
    from app.services.ai_reasoning_service import _normalize_reasoning_output

    normalized = _normalize_reasoning_output(
        raw={
            "attack_graph": {
                "summary": "Database access is one step away from the login endpoint.",
                "risk_overview": "Verified proof already exists.",
                "next_steps": [
                    {
                        "title": "Assign SQLi remediation",
                        "rationale": "The verified SQLi is the fastest risk reducer.",
                        "confidence": 91,
                    }
                ],
                "confidence": 90,
            },
            "report": {
                "draft_summary": "Lead with the verified SQL injection and the suspected IDOR.",
                "prioritization_notes": "Fix the verified issue first.",
                "remediation_focus": ["Use parameterized queries."],
                "confidence": 88,
            },
            "findings": [
                {
                    "title": "Broken Access Control - IDOR",
                    "why_it_matters": "Cross-tenant object access is plausible.",
                    "business_impact": "Sensitive records can leak.",
                    "exploitability_assessment": "High likelihood if auth gaps remain.",
                    "triage_priority": "high",
                    "next_steps": ["Enforce object checks."],
                    "confidence": 89,
                }
            ],
        },
        context=_sample_context(),
    )

    assert normalized["attack_graph"]["confidence"] == 90
    assert normalized["report"]["remediation_focus"] == ["Use parameterized queries."]
    assert normalized["findings"][0]["finding_id"] == "finding-2"
    assert normalized["findings"][0]["title"] == "Broken Access Control - IDOR"


def test_reasoning_config_routes_default_and_deep_models(monkeypatch):
    from app.services import ai_reasoning_service

    monkeypatch.setattr(ai_reasoning_service.settings, "anthropic_model", "legacy-sonnet")
    monkeypatch.setattr(ai_reasoning_service.settings, "anthropic_default_model", "")
    monkeypatch.setattr(ai_reasoning_service.settings, "anthropic_deep_model", "premium-opus")

    default_config = ai_reasoning_service.AIReasoningConfig.from_settings(
        "anthropic",
        "advisory_only",
    )
    deep_config = ai_reasoning_service.AIReasoningConfig.from_settings(
        "anthropic",
        "deep_advisory",
    )

    assert default_config.model == "legacy-sonnet"
    assert deep_config.model == "premium-opus"
    assert default_config.provider == "anthropic"
    assert default_config.advisory_mode == "advisory_only"
    assert deep_config.advisory_mode == "deep_advisory"
    assert default_config.prompt_version.endswith(".advisory_only")
    assert deep_config.prompt_version.endswith(".deep_advisory")


def test_reasoning_config_routes_openai_default_and_deep_models(monkeypatch):
    from app.services import ai_reasoning_service

    monkeypatch.setattr(ai_reasoning_service.settings, "openai_default_model", "gpt-5-mini")
    monkeypatch.setattr(ai_reasoning_service.settings, "openai_deep_model", "gpt-5.4")
    monkeypatch.setattr(ai_reasoning_service.settings, "openai_standard_reasoning_effort", "low")
    monkeypatch.setattr(ai_reasoning_service.settings, "openai_deep_reasoning_effort", "high")

    default_config = ai_reasoning_service.AIReasoningConfig.from_settings(
        "openai",
        "advisory_only",
    )
    deep_config = ai_reasoning_service.AIReasoningConfig.from_settings(
        "openai",
        "deep_advisory",
    )

    assert default_config.provider == "openai"
    assert default_config.model == "gpt-5-mini"
    assert deep_config.model == "gpt-5.4"
    assert default_config.reasoning_effort == "low"
    assert deep_config.reasoning_effort == "high"


def test_provider_chain_prefers_primary_then_fallback(monkeypatch):
    from app.services import ai_reasoning_service

    monkeypatch.setattr(ai_reasoning_service.settings, "ai_reasoning_primary_provider", "anthropic")
    monkeypatch.setattr(ai_reasoning_service.settings, "ai_reasoning_fallback_provider", "openai")

    assert ai_reasoning_service._provider_chain_from_settings() == ["anthropic", "openai"]


def test_extract_openai_output_text_reads_message_content():
    from app.services.ai_reasoning_service import _extract_openai_output_text

    payload = {
        "output": [
            {"type": "file_search_call", "status": "completed"},
            {
                "type": "message",
                "content": [
                    {"type": "output_text", "text": "{\"attack_graph\": {\"summary\": \"ok\"}}"},
                ],
            },
        ]
    }

    assert _extract_openai_output_text(payload) == "{\"attack_graph\": {\"summary\": \"ok\"}}"


def test_build_reasoning_response_preserves_deep_advisory_mode():
    from app.services.ai_reasoning_service import _build_reasoning_response

    artifact = SimpleNamespace(
        id="artifact-1",
        storage_ref="artifacts/demo/deep.json",
        metadata_={"prompt_version": "phase5.advisory.v3.deep_advisory", "context_hash": "abc123"},
        created_at="2026-03-15T00:00:00Z",
    )
    payload = {
        "generated_at": "2026-03-15T00:00:00Z",
        "provider": "anthropic",
        "model": "claude-opus-4-1-20250805",
        "advisory_mode": "deep_advisory",
        "status": "generated",
        "response": {
            "parsed": {
                "attack_graph": {"summary": "Deep mode graph summary."},
                "report": {"draft_summary": "Deep mode report summary."},
                "findings": [],
            }
        },
        "audit": {
            "artifact_id": "artifact-1",
            "storage_ref": "artifacts/demo/deep.json",
            "context_hash": "abc123",
            "prompt_version": "phase5.advisory.v3.deep_advisory",
            "prompt_artifact_type": "ai_reasoning",
        },
    }

    response = _build_reasoning_response(
        scan_id="scan-1",
        artifact=artifact,
        payload=payload,
    )

    assert response["advisory_mode"] == "deep_advisory"
    assert response["model"] == "claude-opus-4-1-20250805"
    assert response["audit"]["prompt_version"] == "phase5.advisory.v3.deep_advisory"
