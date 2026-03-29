from __future__ import annotations

import asyncio
import os
import sys

from pentra_common.config.settings import Settings


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_provider_priority_prefers_explicit_priority_list() -> None:
    from pentra_common.ai.provider_router import provider_priority_from_settings

    settings = Settings(ai_provider_priority="groq, openai, ollama, anthropic, groq")

    assert provider_priority_from_settings(settings) == [
        "groq",
        "openai",
        "ollama",
        "anthropic",
    ]


def test_provider_priority_can_be_limited_to_primary_and_fallback_only() -> None:
    from pentra_common.ai.provider_router import provider_priority_from_settings

    settings = Settings(ai_provider_priority="groq, openai, ollama, anthropic")

    assert provider_priority_from_settings(settings, primary_fallback_only=True) == [
        "groq",
        "openai",
    ]


def test_resolve_provider_chain_supports_ollama_and_groq_for_advisory() -> None:
    from pentra_common.ai.provider_router import resolve_provider_chain

    settings = Settings(
        ai_provider_priority="ollama,groq,openai",
        ollama_default_model="qwen2.5:14b-instruct",
        ollama_base_url="http://127.0.0.1:11434/v1",
        groq_api_key="groq-key",
        groq_default_model="llama-3.3-70b-versatile",
        groq_base_url="https://api.groq.com/openai/v1",
        openai_api_key="openai-key",
        openai_default_model="gpt-4o-mini",
        openai_base_url="https://api.openai.com/v1",
    )

    configs = resolve_provider_chain(
        settings,
        task_type="advisory",
        model_tier="default",
    )

    assert [config.provider for config in configs] == ["ollama", "groq", "openai"]
    assert configs[0].request_surface == "openai_chat_completions"
    assert configs[0].requires_api_key is False
    assert configs[1].request_surface == "openai_chat_completions"
    assert configs[2].request_surface == "openai_responses"


def test_reasoning_service_builds_chat_client_for_groq(monkeypatch) -> None:
    from app.services import ai_reasoning_service
    from app.services.ai_reasoning_service import OpenAICompatibleReasoningClient

    monkeypatch.setattr(ai_reasoning_service.settings, "groq_api_key", "groq-key")
    monkeypatch.setattr(ai_reasoning_service.settings, "groq_default_model", "llama-3.3-70b-versatile")
    monkeypatch.setattr(ai_reasoning_service.settings, "groq_deep_model", "llama-3.3-70b-versatile")
    monkeypatch.setattr(ai_reasoning_service.settings, "groq_base_url", "https://api.groq.com/openai/v1")

    config = ai_reasoning_service.AIReasoningConfig.from_settings("groq", "advisory_only")
    client = ai_reasoning_service._build_provider_client(config)

    assert config.provider == "groq"
    assert config.request_surface == "openai_chat_completions"
    assert isinstance(client, OpenAICompatibleReasoningClient)


def test_provider_diagnostics_reports_priority_and_task_metadata(monkeypatch) -> None:
    from app.services import ai_reasoning_service

    monkeypatch.setattr(ai_reasoning_service.settings, "ai_provider_priority", "groq,gemini,ollama")
    monkeypatch.setattr(ai_reasoning_service.settings, "ai_reasoning_primary_provider", "groq")
    monkeypatch.setattr(ai_reasoning_service.settings, "ai_reasoning_fallback_provider", "gemini")
    monkeypatch.setattr(ai_reasoning_service.settings, "groq_api_key", "groq-key")
    monkeypatch.setattr(ai_reasoning_service.settings, "groq_default_model", "llama-3.3-70b-versatile")
    monkeypatch.setattr(ai_reasoning_service.settings, "groq_deep_model", "llama-3.3-70b-versatile")
    monkeypatch.setattr(ai_reasoning_service.settings, "groq_base_url", "https://api.groq.com/openai/v1")
    monkeypatch.setattr(ai_reasoning_service.settings, "gemini_api_key", "gemini-key")
    monkeypatch.setattr(ai_reasoning_service.settings, "gemini_default_model", "gemini-2.5-flash")
    monkeypatch.setattr(ai_reasoning_service.settings, "gemini_deep_model", "gemini-2.5-pro")
    monkeypatch.setattr(
        ai_reasoning_service.settings,
        "gemini_base_url",
        "https://generativelanguage.googleapis.com/v1beta/openai",
    )
    monkeypatch.setattr(ai_reasoning_service.settings, "ollama_default_model", "qwen2.5:14b-instruct")
    monkeypatch.setattr(ai_reasoning_service.settings, "ollama_deep_model", "qwen2.5:14b-instruct")
    monkeypatch.setattr(ai_reasoning_service.settings, "ollama_base_url", "http://127.0.0.1:11434/v1")

    diagnostics = asyncio.run(ai_reasoning_service.get_ai_provider_diagnostics(live=False))

    assert diagnostics["provider_priority"] == ["groq", "gemini", "ollama"]
    assert diagnostics["effective_provider_priority"] == ["groq", "gemini"]
    advisory = diagnostics["tasks"]["advisory"]
    strategy = diagnostics["tasks"]["strategy"]
    assert [entry["provider"] for entry in advisory] == ["groq", "gemini", "ollama"]
    assert advisory[0]["configured"] is True
    assert advisory[0]["request_surface"] == "openai_chat_completions"
    assert strategy[1]["model"] == "gemini-2.5-pro"


def test_provider_diagnostics_live_probe_reports_generated_status(monkeypatch) -> None:
    from app.services import ai_reasoning_service

    async def fake_probe(resolved) -> dict[str, object]:
        return {
            "status": "generated",
            "latency_ms": 12,
            "preview": f"ok:{resolved.provider}",
        }

    monkeypatch.setattr(ai_reasoning_service.settings, "ai_provider_priority", "groq")
    monkeypatch.setattr(ai_reasoning_service.settings, "groq_api_key", "groq-key")
    monkeypatch.setattr(ai_reasoning_service.settings, "groq_default_model", "llama-3.3-70b-versatile")
    monkeypatch.setattr(ai_reasoning_service.settings, "groq_deep_model", "llama-3.3-70b-versatile")
    monkeypatch.setattr(ai_reasoning_service.settings, "groq_base_url", "https://api.groq.com/openai/v1")
    monkeypatch.setattr(ai_reasoning_service, "_probe_resolved_provider", fake_probe)

    diagnostics = asyncio.run(ai_reasoning_service.get_ai_provider_diagnostics(live=True))

    advisory_probe = diagnostics["tasks"]["advisory"][0]["probe"]
    strategy_probe = diagnostics["tasks"]["strategy"][0]["probe"]
    assert advisory_probe["status"] == "generated"
    assert advisory_probe["preview"] == "ok:groq"
    assert strategy_probe["status"] == "generated"
