from __future__ import annotations

import asyncio
import os
import sys
import uuid

from pentra_common.config.settings import Settings


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def _settings() -> Settings:
    return Settings(
        ai_reasoning_primary_provider="anthropic",
        ai_reasoning_fallback_provider="openai",
        anthropic_api_key="anthropic-key",
        anthropic_default_model="claude-sonnet-4-20250514",
        anthropic_model="claude-sonnet-4-20250514",
        anthropic_base_url="https://api.anthropic.com",
        anthropic_version="2023-06-01",
        openai_api_key="openai-key",
        openai_default_model="gpt-4o-mini",
        openai_base_url="https://api.openai.com/v1",
    )


async def _raise_anthropic(
    self,
    user_message: str,
    *,
    api_key: str,
    model: str,
    base_url: str,
    anthropic_version: str,
) -> str:
    raise RuntimeError("anthropic exhausted")


async def _return_openai(
    self,
    user_message: str,
    *,
    api_key: str,
    model: str,
    base_url: str,
) -> str:
    assert api_key == "openai-key"
    assert model == "gpt-4o-mini"
    return (
        '{"recommended_tools":[{"tool_id":"sqlmap","reason":"verify sql injection","priority":"high"}],'
        '"attack_vectors":["sqli"],"endpoint_focus":["/login"],'
        '"phase_decision":"deep_dive","strategy_notes":"Use sqlmap next.","confidence":0.92}'
    )


async def _return_openai_override(
    self,
    user_message: str,
    *,
    api_key: str,
    model: str,
    base_url: str,
) -> str:
    assert api_key == "env-openai-key"
    assert model == "gpt-4o-mini"
    return (
        '{"recommended_tools":[],"attack_vectors":[],"endpoint_focus":[],"phase_decision":"proceed",'
        '"strategy_notes":"OpenAI provider override engaged.","confidence":0.65}'
    )


async def _return_groq(
    self,
    user_message: str,
    *,
    api_key: str,
    model: str,
    base_url: str,
    provider: str,
) -> str:
    assert provider == "groq"
    assert api_key == "groq-key"
    assert model == "llama-3.3-70b-versatile"
    assert base_url == "https://api.groq.com/openai/v1"
    return (
        '{"recommended_tools":[{"tool_id":"nuclei","reason":"groq-routed follow-up","priority":"medium"}],'
        '"attack_vectors":["template-vuln"],"endpoint_focus":["/graphql"],'
        '"phase_decision":"proceed","strategy_notes":"Groq routing engaged.","confidence":0.71}'
    )


def test_strategy_advisor_falls_back_to_openai_when_anthropic_fails(monkeypatch) -> None:
    from app.engine.ai_strategy_advisor import AIStrategyAdvisor

    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(AIStrategyAdvisor, "_call_anthropic", _raise_anthropic)
    monkeypatch.setattr(AIStrategyAdvisor, "_call_openai", _return_openai)

    advisor = AIStrategyAdvisor(settings=_settings())
    recommendation = asyncio.run(
        advisor.recommend(
            scan_id=uuid.uuid4(),
            phase_completed=3,
            phase_name="vuln",
            findings=[{"severity": "critical", "type": "sql_injection"}],
            scan_config={},
        )
    )

    assert recommendation.provider == "openai"
    assert recommendation.model == "gpt-4o-mini"
    assert recommendation.phase_decision == "deep_dive"
    assert recommendation.recommended_tools[0]["tool_id"] == "sqlmap"


def test_strategy_advisor_openai_override_uses_openai_api_key_env(monkeypatch) -> None:
    from app.engine.ai_strategy_advisor import AIStrategyAdvisor

    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "env-openai-key")
    monkeypatch.delenv("AI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(AIStrategyAdvisor, "_call_openai", _return_openai_override)

    advisor = AIStrategyAdvisor(settings=_settings())
    recommendation = asyncio.run(
        advisor.recommend(
            scan_id=uuid.uuid4(),
            phase_completed=2,
            phase_name="enum",
            findings=[],
            scan_config={},
        )
    )

    assert recommendation.provider == "openai"
    assert recommendation.strategy_notes == "OpenAI provider override engaged."


def test_strategy_advisor_supports_groq_openai_compatible_provider(monkeypatch) -> None:
    from app.engine.ai_strategy_advisor import AIStrategyAdvisor

    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(AIStrategyAdvisor, "_call_openai_compatible", _return_groq)

    advisor = AIStrategyAdvisor(
        settings=Settings(
            ai_provider_priority="groq,openai",
            groq_api_key="groq-key",
            groq_default_model="llama-3.3-70b-versatile",
            groq_base_url="https://api.groq.com/openai/v1",
            openai_api_key="openai-key",
            openai_default_model="gpt-4o-mini",
            openai_base_url="https://api.openai.com/v1",
        )
    )
    recommendation = asyncio.run(
        advisor.recommend(
            scan_id=uuid.uuid4(),
            phase_completed=2,
            phase_name="enum",
            findings=[{"severity": "medium", "type": "graphql"}],
            scan_config={},
        )
    )

    assert recommendation.provider == "groq"
    assert recommendation.model == "llama-3.3-70b-versatile"
    assert recommendation.strategy_notes == "Groq routing engaged."
