from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_openai_responses_payload_omits_reasoning_for_gpt4o_models() -> None:
    from app.services.ai_reasoning_service import (
        AIReasoningConfig,
        _build_openai_responses_request_payload,
    )

    config = AIReasoningConfig(
        provider="openai",
        enabled=True,
        api_key="openai-key",
        model="gpt-4o-mini",
        advisory_mode="advisory_only",
        prompt_version="phase5.advisory.v3.advisory_only",
        base_url="https://api.openai.com/v1",
        anthropic_version=None,
        reasoning_effort="low",
        request_surface="openai_responses",
        requires_api_key=True,
        timeout_seconds=20.0,
        max_retries=1,
        max_tokens=1024,
        temperature=0.2,
    )

    payload = _build_openai_responses_request_payload(
        config,
        system_prompt="system",
        user_prompt="user",
    )

    assert payload["model"] == "gpt-4o-mini"
    assert "reasoning" not in payload


def test_openai_responses_payload_keeps_reasoning_for_gpt5_models() -> None:
    from app.services.ai_reasoning_service import (
        AIReasoningConfig,
        _build_openai_responses_request_payload,
    )

    config = AIReasoningConfig(
        provider="openai",
        enabled=True,
        api_key="openai-key",
        model="gpt-5-mini",
        advisory_mode="advisory_only",
        prompt_version="phase5.advisory.v3.advisory_only",
        base_url="https://api.openai.com/v1",
        anthropic_version=None,
        reasoning_effort="low",
        request_surface="openai_responses",
        requires_api_key=True,
        timeout_seconds=20.0,
        max_retries=1,
        max_tokens=1024,
        temperature=0.2,
    )

    payload = _build_openai_responses_request_payload(
        config,
        system_prompt="system",
        user_prompt="user",
    )

    assert payload["reasoning"] == {"effort": "low"}


def test_summarize_ai_provider_diagnostics_reports_healthy_runtime() -> None:
    from app.services.ai_reasoning_service import summarize_ai_provider_diagnostics

    summary = summarize_ai_provider_diagnostics(
        {
            "enabled": True,
            "tasks": {
                "planner_advisory": [
                    {
                        "provider": "openai",
                        "configured": True,
                        "requires_api_key": True,
                        "api_key_configured": True,
                        "probe": {"status": "generated", "latency_ms": 320},
                    }
                ]
            },
        }
    )

    assert summary["operator_state"] == "configured_and_healthy"
    assert summary["configuration_ready"] is True
    assert summary["configured_provider_count"] == 1
    assert summary["healthy_provider_count"] == 1


def test_summarize_ai_provider_diagnostics_reports_provider_failure_cleanly() -> None:
    from app.services.ai_reasoning_service import summarize_ai_provider_diagnostics

    summary = summarize_ai_provider_diagnostics(
        {
            "enabled": True,
            "tasks": {
                "planner_advisory": [
                    {
                        "provider": "anthropic",
                        "configured": True,
                        "requires_api_key": True,
                        "api_key_configured": True,
                        "probe": {"status": "fallback", "error": "upstream timeout"},
                    }
                ]
            },
        }
    )

    assert summary["operator_state"] == "provider_unreachable"
    assert summary["configuration_ready"] is False
    assert summary["fallback_provider_count"] == 1
    assert summary["last_failure"] == "upstream timeout"
