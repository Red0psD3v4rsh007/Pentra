from __future__ import annotations

import asyncio
import os
import sys
from types import SimpleNamespace


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_bounded_agent_client_prefers_openai_sdk(monkeypatch) -> None:
    from pentra_common.ai.bounded_agent import BoundedAgentClient, BoundedAgentRequest

    captured: dict[str, object] = {}

    class _FakeResponses:
        async def create(self, **kwargs):  # noqa: ANN003
            captured.update(kwargs)
            return SimpleNamespace(
                output_text='{"summary":"ok"}',
                model_dump=lambda: {"output_text": '{"summary":"ok"}'},
            )

    class _FakeAsyncOpenAI:
        def __init__(self, **kwargs):  # noqa: ANN003
            captured["client_kwargs"] = kwargs
            self.responses = _FakeResponses()

    monkeypatch.setattr(
        "pentra_common.ai.bounded_agent._load_openai_sdk",
        lambda: SimpleNamespace(AsyncOpenAI=_FakeAsyncOpenAI),
    )

    response = asyncio.run(
        BoundedAgentClient().generate(
            BoundedAgentRequest(
                provider="openai",
                task_type="advisory",
                model="gpt-4o-mini",
                api_key="openai-key",
                base_url="https://api.openai.com/v1",
                request_surface="openai_responses",
                system_prompt="system",
                user_prompt="user",
                prompt_contract="pentra.ai.advisory",
                context_bundle={"target_profile_hypotheses": [{"key": "spa_rest_api"}]},
            )
        )
    )

    assert response.transport == "openai_sdk"
    assert response.output_text == '{"summary":"ok"}'
    assert captured["model"] == "gpt-4o-mini"


def test_bounded_agent_client_prefers_anthropic_sdk(monkeypatch) -> None:
    from pentra_common.ai.bounded_agent import BoundedAgentClient, BoundedAgentRequest

    class _FakeContent:
        type = "text"
        text = '{"focus_items":[]}'

    class _FakeMessages:
        async def create(self, **kwargs):  # noqa: ANN003
            return SimpleNamespace(
                content=[_FakeContent()],
                model_dump=lambda: {"content": [{"type": "text", "text": '{"focus_items":[]}' }]},
            )

    class _FakeAsyncAnthropic:
        def __init__(self, **kwargs):  # noqa: ANN003
            self.messages = _FakeMessages()

    monkeypatch.setattr(
        "pentra_common.ai.bounded_agent._load_anthropic_sdk",
        lambda: SimpleNamespace(AsyncAnthropic=_FakeAsyncAnthropic),
    )

    response = asyncio.run(
        BoundedAgentClient().generate(
            BoundedAgentRequest(
                provider="anthropic",
                task_type="advisory",
                model="claude-sonnet-4-20250514",
                api_key="anthropic-key",
                base_url="https://api.anthropic.com",
                request_surface="anthropic_messages",
                system_prompt="system",
                user_prompt="user",
                prompt_contract="pentra.ai.advisory",
                context_bundle={"target_profile_hypotheses": [{"key": "spa_rest_api"}]},
                anthropic_version="2023-06-01",
            )
        )
    )

    assert response.transport == "anthropic_sdk"
    assert response.output_text == '{"focus_items":[]}'
