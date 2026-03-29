"""Shared bounded-agent runtime for Pentra advisory and strategy calls.

The goal here is not to make AI a proof authority. It gives the runtime one
well-scoped provider client abstraction so services stop duplicating provider
HTTP branches and can prefer official SDKs when available.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Any, Literal

import httpx

from pentra_common.ai.provider_router import AIRequestSurface, AIProviderName

BoundedAgentTaskType = Literal["advisory", "strategy"]
BoundedAgentResponseFormat = Literal["json_object", "text"]


@dataclass(frozen=True)
class BoundedAgentRequest:
    provider: AIProviderName
    task_type: BoundedAgentTaskType
    model: str
    api_key: str
    base_url: str
    request_surface: AIRequestSurface
    system_prompt: str
    user_prompt: str
    prompt_contract: str
    context_bundle: dict[str, Any]
    response_format: BoundedAgentResponseFormat = "json_object"
    anthropic_version: str | None = None
    reasoning_effort: str | None = None
    timeout_seconds: float = 60.0
    max_tokens: int = 1400
    temperature: float = 0.0


@dataclass(frozen=True)
class BoundedAgentResponse:
    provider: AIProviderName
    model: str
    output_text: str
    raw_payload: dict[str, Any] | list[Any] | None
    transport: str


def pack_context_bundle(*sections: tuple[str, Any]) -> dict[str, Any]:
    """Build an ordered context bundle while skipping empty sections."""
    packed: dict[str, Any] = {}
    for key, value in sections:
        if not key:
            continue
        if value is None:
            continue
        if isinstance(value, (list, tuple, set, dict)) and not value:
            continue
        packed[key] = value
    return packed


def render_context_bundle(context_bundle: dict[str, Any]) -> str:
    return json.dumps(context_bundle, indent=2, sort_keys=False, default=str)


class BoundedAgentClient:
    """Provider client that prefers official SDKs and falls back to HTTP."""

    async def generate(self, request: BoundedAgentRequest) -> BoundedAgentResponse:
        if request.provider == "anthropic":
            return await self._generate_anthropic(request)
        return await self._generate_openai_family(request)

    async def _generate_anthropic(self, request: BoundedAgentRequest) -> BoundedAgentResponse:
        sdk = _load_anthropic_sdk()
        if sdk is not None:
            client = sdk.AsyncAnthropic(api_key=request.api_key, base_url=request.base_url)
            response = await client.messages.create(
                model=request.model,
                max_tokens=request.max_tokens,
                temperature=request.temperature,
                system=request.system_prompt,
                messages=[{"role": "user", "content": request.user_prompt}],
            )
            text_parts: list[str] = []
            for item in getattr(response, "content", []) or []:
                if getattr(item, "type", None) == "text":
                    text = getattr(item, "text", "")
                    if isinstance(text, str) and text.strip():
                        text_parts.append(text)
            output_text = "\n".join(text_parts).strip()
            if not output_text:
                raise RuntimeError("Anthropic SDK response did not include text content.")
            return BoundedAgentResponse(
                provider=request.provider,
                model=request.model,
                output_text=output_text,
                raw_payload=_model_dump(response),
                transport="anthropic_sdk",
            )

        payload = await self._http_post_anthropic(request)
        text_parts = [
            str(item.get("text", ""))
            for item in payload.get("content", [])
            if isinstance(item, dict) and item.get("type") == "text"
        ]
        output_text = "\n".join(part for part in text_parts if part.strip()).strip()
        if not output_text:
            raise RuntimeError("Anthropic response did not include text content.")
        return BoundedAgentResponse(
            provider=request.provider,
            model=request.model,
            output_text=output_text,
            raw_payload=payload,
            transport="httpx_fallback",
        )

    async def _generate_openai_family(self, request: BoundedAgentRequest) -> BoundedAgentResponse:
        sdk = _load_openai_sdk()
        if sdk is not None:
            client = sdk.AsyncOpenAI(
                api_key=request.api_key or None,
                base_url=request.base_url,
                timeout=request.timeout_seconds,
                max_retries=0,
            )
            if request.request_surface == "openai_responses":
                response = await client.responses.create(
                    **_build_openai_responses_kwargs(request)
                )
                output_text = str(getattr(response, "output_text", "") or "").strip()
                if not output_text:
                    raw_payload = _model_dump(response) or {}
                    output_text = _extract_openai_output_text(raw_payload)
                if not output_text:
                    raise RuntimeError("OpenAI responses output_text missing.")
                return BoundedAgentResponse(
                    provider=request.provider,
                    model=request.model,
                    output_text=output_text,
                    raw_payload=_model_dump(response),
                    transport="openai_sdk",
                )

            response = await client.chat.completions.create(
                **_build_openai_chat_kwargs(request)
            )
            raw_payload = _model_dump(response) or {}
            output_text = _extract_openai_chat_completion_text(raw_payload)
            if not output_text:
                raise RuntimeError("OpenAI-compatible chat response did not include assistant content.")
            return BoundedAgentResponse(
                provider=request.provider,
                model=request.model,
                output_text=output_text,
                raw_payload=raw_payload,
                transport="openai_sdk",
            )

        payload = await self._http_post_openai_family(request)
        if request.request_surface == "openai_responses":
            output_text = _extract_openai_output_text(payload)
            if not output_text:
                output_text = str(payload.get("output_text", "") or "").strip()
        else:
            output_text = _extract_openai_chat_completion_text(payload)
        if not output_text:
            raise RuntimeError(f"{request.provider} response did not include text content.")
        return BoundedAgentResponse(
            provider=request.provider,
            model=request.model,
            output_text=output_text,
            raw_payload=payload,
            transport="httpx_fallback",
        )

    async def _http_post_anthropic(self, request: BoundedAgentRequest) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=request.timeout_seconds) as client:
            response = await client.post(
                f"{request.base_url.rstrip('/')}/v1/messages",
                headers={
                    "x-api-key": request.api_key,
                    "anthropic-version": request.anthropic_version or "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": request.model,
                    "max_tokens": request.max_tokens,
                    "temperature": request.temperature,
                    "system": request.system_prompt,
                    "messages": [{"role": "user", "content": request.user_prompt}],
                },
            )
            response.raise_for_status()
            payload = response.json()
            return payload if isinstance(payload, dict) else {}

    async def _http_post_openai_family(self, request: BoundedAgentRequest) -> dict[str, Any]:
        headers = {"content-type": "application/json"}
        if request.api_key.strip():
            headers["authorization"] = f"Bearer {request.api_key}"
        endpoint = "/responses" if request.request_surface == "openai_responses" else "/chat/completions"
        body = (
            _build_openai_responses_kwargs(request)
            if request.request_surface == "openai_responses"
            else _build_openai_chat_kwargs(request)
        )
        async with httpx.AsyncClient(timeout=request.timeout_seconds) as client:
            response = await client.post(
                f"{request.base_url.rstrip('/')}{endpoint}",
                headers=headers,
                json=body,
            )
            response.raise_for_status()
            payload = response.json()
            return payload if isinstance(payload, dict) else {}


def _build_openai_responses_kwargs(request: BoundedAgentRequest) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": request.model,
        "instructions": request.system_prompt,
        "input": request.user_prompt,
        "max_output_tokens": request.max_tokens,
        "store": False,
        "metadata": {
            "app": "pentra",
            "task_type": request.task_type,
            "prompt_contract": request.prompt_contract,
        },
    }
    if request.response_format == "json_object":
        body["text"] = {"format": {"type": "json_object"}}
    else:
        body["text"] = {"format": {"type": "text"}}
    if request.reasoning_effort and _openai_model_supports_reasoning_effort(request.model):
        body["reasoning"] = {"effort": request.reasoning_effort}
    return body


def _build_openai_chat_kwargs(request: BoundedAgentRequest) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": request.model,
        "messages": [
            {"role": "system", "content": request.system_prompt},
            {"role": "user", "content": request.user_prompt},
        ],
        "max_tokens": request.max_tokens,
        "temperature": request.temperature,
    }
    if request.response_format == "json_object":
        body["response_format"] = {"type": "json_object"}
    return body


def _extract_openai_output_text(payload: dict[str, Any]) -> str:
    output = payload.get("output")
    if not isinstance(output, list):
        return ""

    text_parts: list[str] = []
    for item in output:
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if not isinstance(part, dict) or part.get("type") != "output_text":
                continue
            text = str(part.get("text", ""))
            if text.strip():
                text_parts.append(text)
    return "\n".join(text_parts).strip()


def _extract_openai_chat_completion_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""
    message = first.get("message")
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        text_parts: list[str] = []
        for part in content:
            if not isinstance(part, dict):
                continue
            text = part.get("text")
            if isinstance(text, str) and text.strip():
                text_parts.append(text.strip())
        return "\n".join(text_parts).strip()
    return ""


def _openai_model_supports_reasoning_effort(model: str) -> bool:
    normalized = model.strip().lower()
    return normalized.startswith(("gpt-5", "o1", "o3", "o4"))


def _model_dump(value: Any) -> dict[str, Any] | list[Any] | None:
    if value is None:
        return None
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        dumped = model_dump()
        if isinstance(dumped, (dict, list)):
            return dumped
    if isinstance(value, (dict, list)):
        return value
    if hasattr(value, "__dict__"):
        try:
            return asdict(value)
        except Exception:
            return None
    return None


def _load_openai_sdk():
    try:
        import openai  # type: ignore
    except ImportError:
        return None
    return openai


def _load_anthropic_sdk():
    try:
        import anthropic  # type: ignore
    except ImportError:
        return None
    return anthropic
