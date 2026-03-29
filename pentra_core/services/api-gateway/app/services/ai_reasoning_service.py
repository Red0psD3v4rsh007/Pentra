"""Advisory AI reasoning service built on top of persisted scan data.

Phase 5 deliberately keeps AI out of scan execution and exploit decisions.
This service only reads completed scan state, generates advisory reasoning,
and stores every prompt/output for auditability.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from pentra_common.ai.bounded_agent import BoundedAgentClient, BoundedAgentRequest
from pentra_common.config.settings import get_settings
from pentra_common.ai.prompt_contracts import (
    advisory_prompt_contract,
    build_json_user_prompt,
)
from pentra_common.ai.provider_router import (
    ResolvedAIProvider,
    normalize_provider,
    provider_priority_from_settings,
    resolve_provider_chain,
    resolve_provider_config,
)
from pentra_common.storage.artifacts import (
    read_json_artifact,
    sha256_json,
    write_json_artifact,
)
from pentra_common.storage.retention import apply_artifact_retention_metadata

from app.models.attack_graph import ScanArtifact
from app.models.audit_log import AuditLog
from app.models.scan import Scan
from app.services import scan_service

logger = logging.getLogger(__name__)
settings = get_settings()

AIAdvisoryMode = Literal["advisory_only", "deep_advisory"]
AIReasoningProvider = Literal["anthropic", "openai", "groq", "ollama", "gemini", "fallback"]

_DEFAULT_ADVISORY_MODE: AIAdvisoryMode = "advisory_only"
_DEEP_ADVISORY_MODE: AIAdvisoryMode = "deep_advisory"
_PROMPT_VERSION_BASE = "phase5.advisory.v3"
_ADVISORY_ARTIFACT_TYPE = "ai_reasoning"
_FALLBACK_MODEL = "deterministic-fallback"
_DEFAULT_CONTEXT_LIMITS = {
    "findings": 8,
    "evidence": 8,
    "nodes": 24,
    "edges": 32,
}
_DEEP_CONTEXT_LIMITS = {
    "findings": 12,
    "evidence": 14,
    "nodes": 40,
    "edges": 56,
}
_DIAGNOSTICS_PREVIEW_CHARS = 180
_DIAGNOSTICS_SYSTEM_PROMPT = (
    "You are Pentra AI provider diagnostics. "
    "Return compact JSON only."
)
_DIAGNOSTICS_USER_PROMPT = (
    '{"status":"ok","provider_check":"healthy","summary":"Return this object unchanged."}'
)

_BASE_SYSTEM_PROMPT = """You are Pentra AI Advisory.

You are reviewing persisted scan data from an autonomous offensive security
platform. You are advisory only.

Hard rules:
- Do not invent evidence that is not in the provided context.
- Do not recommend out-of-scope or destructive exploitation.
- Do not make job dispatch or exploit-execution decisions.
- Base every conclusion on the supplied findings, graph, report, and evidence.
- Return valid JSON only, with no markdown fences or extra text.

Return this JSON object:
{
  "attack_graph": {
    "summary": "string",
    "risk_overview": "string",
    "next_steps": [
      {"title": "string", "rationale": "string", "confidence": 0}
    ],
    "exploitation_paths": [
      {
        "chain": ["step 1 description", "step 2 description"],
        "impact": "string",
        "likelihood": "high|medium|low",
        "mitre_techniques": ["T1190", "T1059"]
      }
    ],
    "confidence": 0
  },
  "report": {
    "draft_summary": "string",
    "prioritization_notes": "string",
    "remediation_focus": ["string"],
    "attack_surface_assessment": "string",
    "confidence": 0
  },
  "findings": [
    {
      "finding_id": "uuid-or-null",
      "title": "string",
      "why_it_matters": "string",
      "business_impact": "string",
      "exploitability_assessment": "string",
      "exploitation_techniques": ["string"],
      "lateral_movement_potential": "string",
      "triage_priority": "immediate|high|medium|low",
      "next_steps": ["string"],
      "confidence": 0
    }
  ]
}
"""

_DEEP_ADVISORY_APPENDIX = """

Deep Advisory mode instructions:
- Spend more effort connecting multiple findings into credible attack-path pressure.
- Prioritize cross-finding remediation sequencing, not just single-issue severity.
- Highlight where evidence is strong enough to justify human offensive review next.
- Stay bounded to the supplied evidence and keep every next step safe and reviewable.
- Map findings to MITRE ATT&CK techniques where applicable.
- Identify potential lateral movement paths from confirmed vulnerabilities.
- Assess chained exploitation scenarios (e.g., XSS → session theft → privilege escalation).
- Evaluate the full attack surface including API endpoints, authentication boundaries, and data flows.
- Consider supply-chain and dependency vulnerabilities when present.
"""


@dataclass(frozen=True)
class AIReasoningConfig:
    provider: AIReasoningProvider
    enabled: bool
    api_key: str
    model: str
    advisory_mode: AIAdvisoryMode
    prompt_version: str
    base_url: str
    anthropic_version: str | None
    reasoning_effort: str | None
    request_surface: str
    requires_api_key: bool
    timeout_seconds: float
    max_retries: int
    max_tokens: int
    temperature: float

    @classmethod
    def from_settings(
        cls,
        provider: str,
        advisory_mode: str = _DEFAULT_ADVISORY_MODE,
    ) -> "AIReasoningConfig":
        normalized_mode = _normalize_advisory_mode(advisory_mode)
        normalized_provider = normalize_provider(provider) or "anthropic"
        model_tier = "deep" if normalized_mode == _DEEP_ADVISORY_MODE else "default"
        resolved = resolve_provider_config(
            settings,
            provider=normalized_provider,
            task_type="advisory",
            model_tier=model_tier,
        )
        if resolved is None:
            resolved = ResolvedAIProvider(
                provider=normalized_provider,
                task_type="advisory",
                model_tier=model_tier,
                model=_FALLBACK_MODEL,
                api_key="",
                base_url="",
                request_surface="anthropic_messages",
                requires_api_key=True,
            )

        return cls(
            provider=resolved.provider,
            enabled=bool(settings.ai_reasoning_enabled),
            api_key=resolved.api_key,
            model=resolved.model,
            advisory_mode=normalized_mode,
            prompt_version=_prompt_version_for_mode(normalized_mode),
            base_url=resolved.base_url,
            anthropic_version=resolved.anthropic_version,
            reasoning_effort=resolved.reasoning_effort,
            request_surface=resolved.request_surface,
            requires_api_key=resolved.requires_api_key,
            timeout_seconds=float(settings.ai_reasoning_timeout_seconds),
            max_retries=max(int(settings.ai_reasoning_max_retries), 0),
            max_tokens=max(int(settings.ai_reasoning_max_tokens), 256),
            temperature=float(settings.ai_reasoning_temperature),
        )


@dataclass
class AIReasoningRun:
    generated_at: datetime
    provider: AIReasoningProvider
    model: str
    advisory_mode: AIAdvisoryMode
    prompt_version: str
    status: str
    fallback_reason: str | None
    system_prompt: str
    user_prompt: str
    raw_text: str
    parsed: dict[str, Any]


class AnthropicReasoningClient:
    """Minimal Anthropic Messages API client with retry and timeout control."""

    def __init__(self, config: AIReasoningConfig) -> None:
        self._config = config

    async def generate(self, context: dict[str, Any]) -> AIReasoningRun:
        generated_at = datetime.now(timezone.utc)
        system_prompt = _build_system_prompt(self._config.advisory_mode)
        user_prompt = _build_user_prompt(
            context,
            advisory_mode=self._config.advisory_mode,
            prompt_version=self._config.prompt_version,
        )

        if not self._config.enabled:
            return _build_fallback_run(
                context=context,
                generated_at=generated_at,
                advisory_mode=self._config.advisory_mode,
                prompt_version=self._config.prompt_version,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                reason="AI advisory disabled by configuration.",
            )

        if self._config.requires_api_key and not self._config.api_key.strip():
            return _build_fallback_run(
                context=context,
                generated_at=generated_at,
                advisory_mode=self._config.advisory_mode,
                prompt_version=self._config.prompt_version,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                reason="Anthropic API key not configured.",
            )

        raw_text = ""
        try:
            raw_text = await self._call_messages_api(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            parsed = _normalize_reasoning_output(
                raw=_extract_json_payload(raw_text),
                context=context,
            )
            return AIReasoningRun(
                generated_at=generated_at,
                provider="anthropic",
                model=self._config.model,
                advisory_mode=self._config.advisory_mode,
                prompt_version=self._config.prompt_version,
                status="generated",
                fallback_reason=None,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                raw_text=raw_text,
                parsed=parsed,
            )
        except Exception as exc:  # noqa: BLE001 - deliberate fallback boundary
            logger.warning("Anthropic advisory fallback engaged: %s", exc)
            return _build_fallback_run(
                context=context,
                generated_at=generated_at,
                advisory_mode=self._config.advisory_mode,
                prompt_version=self._config.prompt_version,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                reason=_describe_provider_error("Anthropic", exc),
                raw_text=raw_text,
            )

    async def _call_messages_api(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        last_error: Exception | None = None

        for attempt in range(self._config.max_retries + 1):
            try:
                request_payload: dict[str, Any] = {
                    "model": self._config.model,
                    "instructions": system_prompt,
                    "input": user_prompt,
                    "max_output_tokens": self._config.max_tokens,
                    "temperature": self._config.temperature,
                    "store": False,
                    "text": {"format": {"type": "text"}},
                    "metadata": {
                        "app": "pentra",
                        "advisory_mode": self._config.advisory_mode,
                        "prompt_version": self._config.prompt_version,
                    },
                }
                if self._config.reasoning_effort:
                    request_payload["reasoning"] = {
                        "effort": self._config.reasoning_effort,
                    }

                async with httpx.AsyncClient(
                    base_url=self._config.base_url,
                    timeout=self._config.timeout_seconds,
                ) as client:
                    response = await client.post(
                        "/v1/messages",
                        headers={
                            "x-api-key": self._config.api_key,
                            "anthropic-version": self._config.anthropic_version,
                            "content-type": "application/json",
                        },
                        json={
                            "model": self._config.model,
                            "max_tokens": self._config.max_tokens,
                            "temperature": self._config.temperature,
                            "system": system_prompt,
                            "messages": [
                                {
                                    "role": "user",
                                    "content": user_prompt,
                                }
                            ],
                        },
                    )

                if (
                    response.status_code in {408, 409, 429, 500, 502, 503, 504}
                    and attempt < self._config.max_retries
                ):
                    await asyncio.sleep(min(2 ** attempt, 4))
                    continue

                response.raise_for_status()
                payload = response.json()
                text_parts = [
                    str(item.get("text", ""))
                    for item in payload.get("content", [])
                    if isinstance(item, dict) and item.get("type") == "text"
                ]
                result = "\n".join(part for part in text_parts if part.strip()).strip()
                if not result:
                    raise ValueError("Anthropic response did not include text content.")
                return result
            except (
                httpx.TimeoutException,
                httpx.TransportError,
                httpx.HTTPStatusError,
                ValueError,
            ) as exc:
                last_error = exc
                if attempt >= self._config.max_retries:
                    break
                await asyncio.sleep(min(2 ** attempt, 4))

        if last_error is not None:
            raise last_error

        raise RuntimeError("Anthropic advisory request failed without an explicit provider error.")


class OpenAIReasoningClient:
    """Minimal OpenAI Responses API client with retry and timeout control."""

    def __init__(self, config: AIReasoningConfig) -> None:
        self._config = config

    async def generate(self, context: dict[str, Any]) -> AIReasoningRun:
        generated_at = datetime.now(timezone.utc)
        system_prompt = _build_system_prompt(self._config.advisory_mode)
        user_prompt = _build_user_prompt(
            context,
            advisory_mode=self._config.advisory_mode,
            prompt_version=self._config.prompt_version,
        )

        if not self._config.enabled:
            return _build_fallback_run(
                context=context,
                generated_at=generated_at,
                advisory_mode=self._config.advisory_mode,
                prompt_version=self._config.prompt_version,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                reason="AI advisory disabled by configuration.",
            )

        if self._config.requires_api_key and not self._config.api_key.strip():
            return _build_fallback_run(
                context=context,
                generated_at=generated_at,
                advisory_mode=self._config.advisory_mode,
                prompt_version=self._config.prompt_version,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                reason="OpenAI API key not configured.",
            )

        raw_text = ""
        try:
            raw_text = await self._call_responses_api(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            parsed = _normalize_reasoning_output(
                raw=_extract_json_payload(raw_text),
                context=context,
            )
            return AIReasoningRun(
                generated_at=generated_at,
                provider="openai",
                model=self._config.model,
                advisory_mode=self._config.advisory_mode,
                prompt_version=self._config.prompt_version,
                status="generated",
                fallback_reason=None,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                raw_text=raw_text,
                parsed=parsed,
            )
        except Exception as exc:  # noqa: BLE001 - deliberate fallback boundary
            logger.warning("OpenAI advisory fallback engaged: %s", exc)
            return _build_fallback_run(
                context=context,
                generated_at=generated_at,
                advisory_mode=self._config.advisory_mode,
                prompt_version=self._config.prompt_version,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                reason=_describe_provider_error("OpenAI", exc),
                raw_text=raw_text,
            )

    async def _call_responses_api(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        last_error: Exception | None = None

        for attempt in range(self._config.max_retries + 1):
            try:
                request_payload = _build_openai_responses_request_payload(
                    self._config,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                )

                async with httpx.AsyncClient(
                    base_url=self._config.base_url,
                    timeout=self._config.timeout_seconds,
                ) as client:
                    response = await client.post(
                        "/responses",
                        headers={
                            "authorization": f"Bearer {self._config.api_key}",
                            "content-type": "application/json",
                        },
                        json=request_payload,
                    )

                if (
                    response.status_code in {408, 409, 429, 500, 502, 503, 504}
                    and attempt < self._config.max_retries
                ):
                    await asyncio.sleep(min(2 ** attempt, 4))
                    continue

                response.raise_for_status()
                payload = response.json()
                result = _extract_openai_output_text(payload)
                if not result:
                    raise ValueError("OpenAI response did not include text content.")
                return result
            except (
                httpx.TimeoutException,
                httpx.TransportError,
                httpx.HTTPStatusError,
                ValueError,
            ) as exc:
                last_error = exc
                if attempt >= self._config.max_retries:
                    break
                await asyncio.sleep(min(2 ** attempt, 4))

        if last_error is not None:
            raise last_error

        raise RuntimeError("OpenAI advisory request failed without an explicit provider error.")


class OpenAICompatibleReasoningClient:
    """Chat-completions client for Groq, Ollama, Gemini, and similar APIs."""

    def __init__(self, config: AIReasoningConfig) -> None:
        self._config = config

    async def generate(self, context: dict[str, Any]) -> AIReasoningRun:
        generated_at = datetime.now(timezone.utc)
        system_prompt = _build_system_prompt(self._config.advisory_mode)
        user_prompt = _build_user_prompt(
            context,
            advisory_mode=self._config.advisory_mode,
            prompt_version=self._config.prompt_version,
        )

        if not self._config.enabled:
            return _build_fallback_run(
                context=context,
                generated_at=generated_at,
                advisory_mode=self._config.advisory_mode,
                prompt_version=self._config.prompt_version,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                reason="AI advisory disabled by configuration.",
            )

        if self._config.requires_api_key and not self._config.api_key.strip():
            return _build_fallback_run(
                context=context,
                generated_at=generated_at,
                advisory_mode=self._config.advisory_mode,
                prompt_version=self._config.prompt_version,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                reason=f"{self._config.provider} API key not configured.",
            )

        raw_text = ""
        try:
            raw_text = await self._call_chat_completions_api(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            parsed = _normalize_reasoning_output(
                raw=_extract_json_payload(raw_text),
                context=context,
            )
            return AIReasoningRun(
                generated_at=generated_at,
                provider=self._config.provider,
                model=self._config.model,
                advisory_mode=self._config.advisory_mode,
                prompt_version=self._config.prompt_version,
                status="generated",
                fallback_reason=None,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                raw_text=raw_text,
                parsed=parsed,
            )
        except Exception as exc:  # noqa: BLE001 - deliberate fallback boundary
            logger.warning("%s advisory fallback engaged: %s", self._config.provider, exc)
            return _build_fallback_run(
                context=context,
                generated_at=generated_at,
                advisory_mode=self._config.advisory_mode,
                prompt_version=self._config.prompt_version,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                reason=_describe_provider_error(self._config.provider.capitalize(), exc),
                raw_text=raw_text,
            )

    async def _call_chat_completions_api(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        last_error: Exception | None = None

        for attempt in range(self._config.max_retries + 1):
            try:
                headers = {"content-type": "application/json"}
                if self._config.api_key.strip():
                    headers["authorization"] = f"Bearer {self._config.api_key}"

                async with httpx.AsyncClient(
                    base_url=self._config.base_url,
                    timeout=self._config.timeout_seconds,
                ) as client:
                    response = await client.post(
                        "/chat/completions",
                        headers=headers,
                        json={
                            "model": self._config.model,
                            "max_tokens": self._config.max_tokens,
                            "temperature": self._config.temperature,
                            "messages": [
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_prompt},
                            ],
                        },
                    )

                if (
                    response.status_code in {408, 409, 429, 500, 502, 503, 504}
                    and attempt < self._config.max_retries
                ):
                    await asyncio.sleep(min(2 ** attempt, 4))
                    continue

                response.raise_for_status()
                payload = response.json()
                result = _extract_openai_chat_completion_text(payload)
                if not result:
                    raise ValueError("OpenAI-compatible response did not include text content.")
                return result
            except (
                httpx.TimeoutException,
                httpx.TransportError,
                httpx.HTTPStatusError,
                ValueError,
            ) as exc:
                last_error = exc
                if attempt >= self._config.max_retries:
                    break
                await asyncio.sleep(min(2 ** attempt, 4))

        if last_error is not None:
            raise last_error

        raise RuntimeError("OpenAI-compatible advisory request failed without an explicit provider error.")


def _describe_provider_error(provider_label: str, exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        message = ""
        try:
            payload = exc.response.json()
        except ValueError:
            payload = None

        if isinstance(payload, dict):
            error_payload = payload.get("error")
            if isinstance(error_payload, dict):
                detail = error_payload.get("message")
                if isinstance(detail, str) and detail.strip():
                    message = detail.strip()
            else:
                detail = payload.get("detail")
                if isinstance(detail, str) and detail.strip():
                    message = detail.strip()

        if not message:
            body_text = exc.response.text.strip()
            if body_text:
                message = body_text

        if message:
            return (
                f"{provider_label} advisory request failed ({exc.response.status_code}): "
                f"{message}"
            )

    return f"{provider_label} advisory request failed: {exc}"


def _extract_openai_output_text(payload: dict[str, Any]) -> str:
    output = payload.get("output")
    if not isinstance(output, list):
        return ""

    text_parts: list[str] = []
    for item in output:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "message":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if not isinstance(part, dict):
                continue
            if part.get("type") != "output_text":
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


def _build_openai_responses_request_payload(
    config: AIReasoningConfig,
    *,
    system_prompt: str,
    user_prompt: str,
) -> dict[str, Any]:
    request_payload: dict[str, Any] = {
        "model": config.model,
        "instructions": system_prompt,
        "input": user_prompt,
        "max_output_tokens": config.max_tokens,
        "temperature": config.temperature,
        "store": False,
        "text": {"format": {"type": "text"}},
        "metadata": {
            "app": "pentra",
            "advisory_mode": config.advisory_mode,
            "prompt_version": config.prompt_version,
        },
    }
    if (
        config.reasoning_effort
        and _openai_model_supports_reasoning_effort(config.model)
    ):
        request_payload["reasoning"] = {
            "effort": config.reasoning_effort,
        }
    return request_payload


def _normalize_advisory_mode(advisory_mode: str | None) -> AIAdvisoryMode:
    if advisory_mode == _DEEP_ADVISORY_MODE:
        return _DEEP_ADVISORY_MODE
    return _DEFAULT_ADVISORY_MODE


def _normalize_provider(provider: str | None) -> AIReasoningProvider | None:
    normalized = normalize_provider(provider)
    if normalized in {"anthropic", "openai", "groq", "ollama", "gemini"}:
        return normalized
    return None


def _provider_chain_from_settings() -> list[AIReasoningProvider]:
    resolved = resolve_provider_chain(
        settings,
        task_type="advisory",
        model_tier="default",
    )
    chain = [config.provider for config in resolved]
    return chain or ["anthropic"]


async def get_ai_provider_diagnostics(*, live: bool = False) -> dict[str, Any]:
    """Return configured AI provider routing and optional live probe results."""
    generated_at = datetime.now(timezone.utc).isoformat()
    priority = provider_priority_from_settings(settings)
    effective_priority = provider_priority_from_settings(
        settings,
        primary_fallback_only=True,
    )
    tasks: dict[str, list[dict[str, Any]]] = {}

    for task_type, model_tier in (("advisory", "default"), ("strategy", "deep")):
        provider_entries: list[dict[str, Any]] = []
        for provider in priority:
            resolved = resolve_provider_config(
                settings,
                provider=provider,
                task_type=task_type,  # type: ignore[arg-type]
                model_tier=model_tier,  # type: ignore[arg-type]
            )
            entry: dict[str, Any] = {
                "provider": provider,
                "task_type": task_type,
                "model_tier": model_tier,
                "configured": resolved is not None,
                "model": resolved.model if resolved is not None else "",
                "base_url": resolved.base_url if resolved is not None else "",
                "request_surface": resolved.request_surface if resolved is not None else "",
                "requires_api_key": (
                    resolved.requires_api_key if resolved is not None else True
                ),
                "api_key_configured": (
                    bool(resolved.api_key.strip()) if resolved is not None else False
                ),
            }
            if live:
                if resolved is None:
                    entry["probe"] = {
                        "status": "skipped",
                        "error": "Provider is not fully configured.",
                    }
                else:
                    entry["probe"] = await _probe_resolved_provider(resolved)
            entry["operator_state"] = _provider_operator_state(
                enabled=bool(settings.ai_reasoning_enabled),
                configured=bool(entry["configured"]),
                api_key_configured=bool(entry["api_key_configured"]),
                probe=entry.get("probe"),
            )
            provider_entries.append(entry)
        tasks[task_type] = provider_entries

    summary = summarize_ai_provider_diagnostics(
        {
            "generated_at": generated_at,
            "enabled": bool(settings.ai_reasoning_enabled),
            "provider_priority": priority,
            "effective_provider_priority": effective_priority,
            "tasks": tasks,
        }
    )
    return {
        "generated_at": generated_at,
        "enabled": bool(settings.ai_reasoning_enabled),
        "provider_priority": priority,
        "effective_provider_priority": effective_priority,
        "tasks": tasks,
        **summary,
    }


def summarize_ai_provider_diagnostics(payload: dict[str, Any]) -> dict[str, Any]:
    enabled = bool(payload.get("enabled"))
    tasks = payload.get("tasks") or {}
    provider_entries = [
        entry
        for task_entries in tasks.values()
        if isinstance(task_entries, list)
        for entry in task_entries
        if isinstance(entry, dict)
    ]
    configured_entries = [
        entry
        for entry in provider_entries
        if bool(entry.get("configured"))
        and (
            not bool(entry.get("requires_api_key"))
            or bool(entry.get("api_key_configured"))
        )
    ]
    healthy_entries = [
        entry
        for entry in configured_entries
        if isinstance(entry.get("probe"), dict) and entry["probe"].get("status") == "generated"
    ]
    fallback_entries = [
        entry
        for entry in configured_entries
        if isinstance(entry.get("probe"), dict) and entry["probe"].get("status") == "fallback"
    ]
    last_failure = next(
        (
            str(entry["probe"].get("error"))
            for entry in fallback_entries
            if isinstance(entry.get("probe"), dict) and str(entry["probe"].get("error") or "").strip()
        ),
        None,
    )

    if not enabled:
        operator_state = "disabled_by_config"
    elif not configured_entries:
        operator_state = "missing_api_key"
    elif healthy_entries:
        operator_state = "configured_and_healthy"
    elif fallback_entries:
        operator_state = "provider_unreachable"
    else:
        operator_state = "configured_but_fallback"

    return {
        "operator_state": operator_state,
        "configuration_ready": operator_state in {"configured_and_healthy", "configured_but_fallback"},
        "configured_provider_count": len(configured_entries),
        "healthy_provider_count": len(healthy_entries),
        "fallback_provider_count": len(fallback_entries),
        "last_failure": last_failure,
    }


def _provider_operator_state(
    *,
    enabled: bool,
    configured: bool,
    api_key_configured: bool,
    probe: dict[str, Any] | None,
) -> str:
    if not enabled:
        return "disabled_by_config"
    if not configured or not api_key_configured:
        return "missing_api_key"
    if isinstance(probe, dict) and probe.get("status") == "generated":
        return "configured_and_healthy"
    if isinstance(probe, dict) and probe.get("status") == "fallback":
        return "provider_unreachable"
    return "configured_but_fallback"


def _diagnostic_config_from_resolved(resolved: ResolvedAIProvider) -> AIReasoningConfig:
    advisory_mode = (
        _DEEP_ADVISORY_MODE if resolved.model_tier == "deep" else _DEFAULT_ADVISORY_MODE
    )
    return AIReasoningConfig(
        provider=resolved.provider,
        enabled=bool(settings.ai_reasoning_enabled),
        api_key=resolved.api_key,
        model=resolved.model,
        advisory_mode=advisory_mode,
        prompt_version=_prompt_version_for_mode(advisory_mode),
        base_url=resolved.base_url,
        anthropic_version=resolved.anthropic_version,
        reasoning_effort=resolved.reasoning_effort,
        request_surface=resolved.request_surface,
        requires_api_key=resolved.requires_api_key,
        timeout_seconds=float(settings.ai_reasoning_timeout_seconds),
        max_retries=0,
        max_tokens=160,
        temperature=0.0,
    )


async def _probe_resolved_provider(resolved: ResolvedAIProvider) -> dict[str, Any]:
    config = _diagnostic_config_from_resolved(resolved)
    started = time.monotonic()
    try:
        raw_text = (
            await BoundedAgentClient().generate(
                BoundedAgentRequest(
                    provider=resolved.provider,
                    task_type="advisory",
                    model=resolved.model,
                    api_key=resolved.api_key,
                    base_url=resolved.base_url,
                    request_surface=resolved.request_surface,
                    system_prompt=_DIAGNOSTICS_SYSTEM_PROMPT,
                    user_prompt=_DIAGNOSTICS_USER_PROMPT,
                    prompt_contract="pentra.ai.diagnostics",
                    context_bundle={"diagnostics": True},
                    anthropic_version=resolved.anthropic_version,
                    reasoning_effort=resolved.reasoning_effort,
                    timeout_seconds=float(settings.ai_reasoning_timeout_seconds),
                    max_tokens=160,
                    temperature=0.0,
                    response_format="json_object",
                )
            )
        ).output_text

        latency_ms = int((time.monotonic() - started) * 1000)
        return {
            "status": "generated",
            "latency_ms": latency_ms,
            "preview": _truncate(raw_text, _DIAGNOSTICS_PREVIEW_CHARS),
        }
    except Exception as exc:  # noqa: BLE001 - diagnostics must not hard-fail
        latency_ms = int((time.monotonic() - started) * 1000)
        return {
            "status": "fallback",
            "latency_ms": latency_ms,
            "error": _describe_provider_error(resolved.provider.capitalize(), exc),
        }


def _prompt_version_for_mode(advisory_mode: AIAdvisoryMode) -> str:
    return advisory_prompt_contract(advisory_mode).prompt_version


def _build_system_prompt(advisory_mode: AIAdvisoryMode) -> str:
    if advisory_mode == _DEEP_ADVISORY_MODE:
        return f"{_BASE_SYSTEM_PROMPT.rstrip()}{_DEEP_ADVISORY_APPENDIX}"
    return _BASE_SYSTEM_PROMPT


def _context_limits_for_mode(advisory_mode: AIAdvisoryMode) -> dict[str, int]:
    if advisory_mode == _DEEP_ADVISORY_MODE:
        return _DEEP_CONTEXT_LIMITS
    return _DEFAULT_CONTEXT_LIMITS


async def _release_read_transaction(session: AsyncSession) -> None:
    """End the current read transaction before slow external provider calls."""
    if session.in_transaction():
        await session.commit()


async def get_scan_ai_reasoning(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    session: AsyncSession,
    refresh: bool = False,
    advisory_mode: str = _DEFAULT_ADVISORY_MODE,
) -> dict[str, Any] | None:
    """Generate or fetch cached advisory reasoning for a scan."""
    normalized_mode = _normalize_advisory_mode(advisory_mode)
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id, Scan.tenant_id == tenant_id)
        .options(selectinload(Scan.asset), selectinload(Scan.findings))
    )
    scan = (await session.execute(stmt)).scalar_one_or_none()
    if scan is None:
        return None

    graph = await scan_service.get_attack_graph(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    report = await scan_service.get_scan_report(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    evidence = await scan_service.list_evidence_references(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    context = _build_reasoning_context(
        scan=scan,
        graph=graph,
        report=report,
        evidence=evidence,
        advisory_mode=normalized_mode,
    )
    context_hash = sha256_json(context)

    if not refresh:
        cached = await _load_cached_reasoning(
            scan_id=scan_id,
            session=session,
            context_hash=context_hash,
            advisory_mode=normalized_mode,
        )
        if cached is not None:
            return cached

    await _release_read_transaction(session)
    run = await _generate_reasoning_run(
        context=context,
        advisory_mode=normalized_mode,
    )
    artifact = await _store_reasoning_artifact(
        scan=scan,
        session=session,
        context_hash=context_hash,
        context=context,
        run=run,
    )
    await _record_reasoning_audit(
        session=session,
        tenant_id=tenant_id,
        user_id=user_id,
        scan_id=scan_id,
        artifact=artifact,
        run=run,
        context_hash=context_hash,
    )
    return _build_reasoning_response(
        scan_id=scan_id,
        artifact=artifact,
        payload=_artifact_payload_for_response(
            artifact=artifact,
            context_hash=context_hash,
            run=run,
        ),
    )


async def _generate_reasoning_run(
    *,
    context: dict[str, Any],
    advisory_mode: AIAdvisoryMode,
) -> AIReasoningRun:
    prompt_version = _prompt_version_for_mode(advisory_mode)
    system_prompt = _build_system_prompt(advisory_mode)
    user_prompt = _build_user_prompt(
        context,
        advisory_mode=advisory_mode,
        prompt_version=prompt_version,
    )

    if not settings.ai_reasoning_enabled:
        return _build_fallback_run(
            context=context,
            generated_at=datetime.now(timezone.utc),
            advisory_mode=advisory_mode,
            prompt_version=prompt_version,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            reason="AI advisory disabled by configuration.",
        )

    failure_reasons: list[str] = []
    for provider in _provider_chain_from_settings():
        config = AIReasoningConfig.from_settings(provider, advisory_mode)
        run = await _generate_provider_run_with_bounded_client(
            context=context,
            advisory_mode=advisory_mode,
            config=config,
        )
        if run.status == "generated":
            return run
        if run.fallback_reason:
            failure_reasons.append(run.fallback_reason)

    return _build_fallback_run(
        context=context,
        generated_at=datetime.now(timezone.utc),
        advisory_mode=advisory_mode,
        prompt_version=prompt_version,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        reason=" | ".join(failure_reasons) or "No advisory provider was able to generate a response.",
    )


async def _generate_provider_run_with_bounded_client(
    *,
    context: dict[str, Any],
    advisory_mode: AIAdvisoryMode,
    config: AIReasoningConfig,
) -> AIReasoningRun:
    generated_at = datetime.now(timezone.utc)
    system_prompt = _build_system_prompt(config.advisory_mode)
    user_prompt = _build_user_prompt(
        context,
        advisory_mode=advisory_mode,
        prompt_version=config.prompt_version,
    )

    if not config.enabled:
        return _build_fallback_run(
            context=context,
            generated_at=generated_at,
            advisory_mode=config.advisory_mode,
            prompt_version=config.prompt_version,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            reason="AI advisory disabled by configuration.",
        )

    if config.requires_api_key and not config.api_key.strip():
        return _build_fallback_run(
            context=context,
            generated_at=generated_at,
            advisory_mode=config.advisory_mode,
            prompt_version=config.prompt_version,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            reason=f"{config.provider.capitalize()} API key not configured.",
        )

    raw_text = ""
    try:
        response = await BoundedAgentClient().generate(
            BoundedAgentRequest(
                provider=config.provider if config.provider != "fallback" else "openai",
                task_type="advisory",
                model=config.model,
                api_key=config.api_key,
                base_url=config.base_url,
                request_surface=config.request_surface,  # type: ignore[arg-type]
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                prompt_contract=config.prompt_version,
                context_bundle=context,
                anthropic_version=config.anthropic_version,
                reasoning_effort=config.reasoning_effort,
                timeout_seconds=config.timeout_seconds,
                max_tokens=config.max_tokens,
                temperature=config.temperature,
                response_format="json_object",
            )
        )
        raw_text = response.output_text
        parsed = _normalize_reasoning_output(
            raw=_extract_json_payload(raw_text),
            context=context,
        )
        return AIReasoningRun(
            generated_at=generated_at,
            provider=config.provider,
            model=config.model,
            advisory_mode=config.advisory_mode,
            prompt_version=config.prompt_version,
            status="generated",
            fallback_reason=None,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            raw_text=raw_text,
            parsed=parsed,
        )
    except Exception as exc:  # noqa: BLE001 - deliberate fallback boundary
        return _build_fallback_run(
            context=context,
            generated_at=generated_at,
            advisory_mode=config.advisory_mode,
            prompt_version=config.prompt_version,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            reason=_describe_provider_error(config.provider.capitalize(), exc),
            raw_text=raw_text,
        )


def _build_provider_client(
    config: AIReasoningConfig,
) -> AnthropicReasoningClient | OpenAIReasoningClient | OpenAICompatibleReasoningClient:
    if config.request_surface == "openai_responses":
        return OpenAIReasoningClient(config)
    if config.request_surface == "openai_chat_completions":
        return OpenAICompatibleReasoningClient(config)
    return AnthropicReasoningClient(config)


def _build_user_prompt(
    context: dict[str, Any],
    *,
    advisory_mode: AIAdvisoryMode,
    prompt_version: str,
) -> str:
    contract = advisory_prompt_contract(advisory_mode)
    if contract.prompt_version != prompt_version:
        contract = type(contract)(
            contract_id=contract.contract_id,
            prompt_version=prompt_version,
            task_type=contract.task_type,
            response_format=contract.response_format,
        )
    return build_json_user_prompt(
        contract,
        context=context,
        preamble=(
            "Generate advisory reasoning for this Pentra scan context. "
            "Keep recommendations bounded, evidence-based, and safe."
        ),
    )


def _build_reasoning_context(
    *,
    scan: Scan,
    graph: dict[str, Any] | None,
    report: dict[str, Any] | None,
    evidence: list[dict[str, Any]],
    advisory_mode: AIAdvisoryMode,
) -> dict[str, Any]:
    limits = _context_limits_for_mode(advisory_mode)
    findings = sorted(
        scan.findings,
        key=lambda finding: (
            -scan_service._verification_rank(scan_service._verification_state_for_finding(finding)),
            -scan_service._severity_rank(str(finding.severity)),
            -int(finding.confidence or 0),
            finding.created_at,
        ),
    )
    graph_payload = graph or scan_service._empty_attack_graph_payload(scan)
    report_payload = report or {
        "executive_summary": "No persisted report available yet.",
        "severity_counts": {key: 0 for key in ("critical", "high", "medium", "low", "info")},
        "verification_counts": {"verified": 0, "suspected": 0, "detected": 0},
        "top_findings": [],
        "vulnerability_count": 0,
        "evidence_count": 0,
    }

    prepared_findings = []
    for finding in findings[: limits["findings"]]:
        evidence_payload = finding.evidence if isinstance(finding.evidence, dict) else {}
        prepared_findings.append(
            {
                "finding_id": str(finding.id),
                "title": finding.title,
                "severity": str(finding.severity),
                "confidence": int(finding.confidence or 0),
                "verification_state": scan_service._verification_state_for_finding(finding),
                "verification_confidence": getattr(finding, "verification_confidence", None),
                "source_type": str(finding.source_type),
                "tool_source": finding.tool_source,
                "exploitability": getattr(finding, "exploitability", None),
                "surface": getattr(finding, "surface", None),
                "description": _truncate(finding.description, 320),
                "remediation": _truncate(finding.remediation, 220),
                "target": str(
                    evidence_payload.get("endpoint")
                    or evidence_payload.get("target")
                    or scan.asset.target
                ),
            }
        )

    graph_nodes = graph_payload.get("nodes", [])
    graph_edges = graph_payload.get("edges", [])

    return {
        "scan": {
            "scan_id": str(scan.id),
            "tenant_id": str(scan.tenant_id),
            "advisory_mode": advisory_mode,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "priority": scan.priority,
            "asset_type": scan.asset.asset_type if scan.asset is not None else "unknown",
            "asset_name": scan.asset.name if scan.asset is not None else str(scan.asset_id),
            "asset_target": scan.asset.target if scan.asset is not None else str(scan.asset_id),
            "profile_id": scan.config.get("profile_id") if isinstance(scan.config, dict) else None,
        },
        "report": {
            "executive_summary": report_payload.get("executive_summary"),
            "severity_counts": report_payload.get("severity_counts", {}),
            "verification_counts": report_payload.get("verification_counts", {}),
            "vulnerability_count": report_payload.get("vulnerability_count", 0),
            "evidence_count": report_payload.get("evidence_count", 0),
            "top_findings": report_payload.get("top_findings", [])[:5],
        },
        "graph": {
            "node_count": graph_payload.get("node_count", 0),
            "edge_count": graph_payload.get("edge_count", 0),
            "path_summary": graph_payload.get("path_summary", {}),
            "scoring_summary": graph_payload.get("scoring_summary", {}),
            "nodes": [
                {
                    "id": node.get("id"),
                    "node_type": node.get("node_type"),
                    "label": node.get("label"),
                }
                for node in graph_nodes[: limits["nodes"]]
                if isinstance(node, dict)
            ],
            "edges": [
                {
                    "source": edge.get("source"),
                    "target": edge.get("target"),
                    "edge_type": edge.get("edge_type"),
                }
                for edge in graph_edges[: limits["edges"]]
                if isinstance(edge, dict)
            ],
        },
        "findings": prepared_findings,
        "evidence": [
            {
                "id": item.get("id"),
                "finding_title": item.get("finding_title"),
                "severity": item.get("severity"),
                "evidence_type": item.get("evidence_type"),
                "label": item.get("label"),
                "target": item.get("target"),
                "content_preview": _truncate(item.get("content_preview"), 200),
            }
            for item in evidence[: limits["evidence"]]
        ],
    }


def _build_fallback_run(
    *,
    context: dict[str, Any],
    generated_at: datetime,
    advisory_mode: AIAdvisoryMode,
    prompt_version: str,
    system_prompt: str,
    user_prompt: str,
    reason: str,
    raw_text: str = "",
) -> AIReasoningRun:
    return AIReasoningRun(
        generated_at=generated_at,
        provider="fallback",
        model=_FALLBACK_MODEL,
        advisory_mode=advisory_mode,
        prompt_version=prompt_version,
        status="fallback" if settings.ai_reasoning_enabled else "disabled",
        fallback_reason=reason,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        raw_text=raw_text,
        parsed=_build_fallback_advisory(context),
    )


def _build_fallback_advisory(context: dict[str, Any]) -> dict[str, Any]:
    report = context.get("report", {})
    graph = context.get("graph", {})
    findings = context.get("findings", [])
    asset_target = str(context.get("scan", {}).get("asset_target", "the target"))
    severity_counts = report.get("severity_counts", {}) if isinstance(report, dict) else {}
    verification_counts = report.get("verification_counts", {}) if isinstance(report, dict) else {}

    attack_paths = graph.get("path_summary", {}) if isinstance(graph, dict) else {}
    targets_reached = attack_paths.get("targets_reached", []) if isinstance(attack_paths, dict) else []
    critical = int(severity_counts.get("critical", 0) or 0)
    high = int(severity_counts.get("high", 0) or 0)
    verified = int(verification_counts.get("verified", 0) or 0)
    suspected = int(verification_counts.get("suspected", 0) or 0)

    risk_overview_parts = []
    if critical:
        risk_overview_parts.append(f"{critical} critical finding(s)")
    if high:
        risk_overview_parts.append(f"{high} high finding(s)")
    if verified:
        risk_overview_parts.append(f"{verified} verified")
    if suspected:
        risk_overview_parts.append(f"{suspected} suspected")
    if not risk_overview_parts:
        risk_overview_parts.append("no persisted high-signal findings yet")

    next_steps = _fallback_next_steps(context)
    finding_advisories = [
        _fallback_finding_advisory(finding)
        for finding in findings[: _context_limits_for_mode(
            _normalize_advisory_mode(context.get("scan", {}).get("advisory_mode"))
        )["findings"]]
    ]

    return {
        "attack_graph": {
            "summary": (
                f"Pentra mapped {graph.get('node_count', 0)} graph nodes and "
                f"{graph.get('edge_count', 0)} edges for {asset_target}. "
                f"Targets reached: {', '.join(targets_reached) if targets_reached else 'no terminal path yet'}."
            ),
            "risk_overview": (
                "Current offensive posture: " + ", ".join(risk_overview_parts) + "."
            ),
            "next_steps": next_steps,
            "confidence": 72 if findings else 58,
        },
        "report": {
            "draft_summary": (
                f"{report.get('executive_summary') or 'Persisted scan results are available.'} "
                "Use verified issues first when assigning remediation owners."
            ),
            "prioritization_notes": (
                "Prioritize verified and internet-reachable issues first, then cluster "
                "suspected issues by shared surface and remediation owner."
            ),
            "remediation_focus": _fallback_remediation_focus(findings),
            "confidence": 74 if findings else 60,
        },
        "findings": finding_advisories,
    }


def _fallback_next_steps(context: dict[str, Any]) -> list[dict[str, Any]]:
    findings = context.get("findings", [])
    report = context.get("report", {})
    graph = context.get("graph", {})

    steps: list[dict[str, Any]] = []
    if any(finding.get("verification_state") != "verified" for finding in findings):
        steps.append(
            {
                "title": "Retest highest-signal unresolved findings",
                "rationale": (
                    "Verified issues should stay first, but unverified critical/high findings "
                    "still need bounded proof or dismissal before closing the scan."
                ),
                "confidence": 86,
            }
        )

    if int(graph.get("node_count", 0) or 0) > 0:
        steps.append(
            {
                "title": "Trace the shortest exposed path to impact",
                "rationale": (
                    "Use the persisted graph to focus on endpoints and vulnerabilities that "
                    "connect directly to privilege or data-impact nodes."
                ),
                "confidence": 81,
            }
        )

    if int(report.get("verification_counts", {}).get("verified", 0) or 0) > 0:
        steps.append(
            {
                "title": "Assign remediation owners to proven findings",
                "rationale": (
                    "Verified findings are the fastest trust-building path for engineering "
                    "because they already carry concrete evidence."
                ),
                "confidence": 88,
            }
        )

    return steps[:3]


def _fallback_remediation_focus(findings: list[dict[str, Any]]) -> list[str]:
    focus: list[str] = []
    for finding in findings[:5]:
        remediation = str(finding.get("remediation") or "").strip()
        title = str(finding.get("title") or "finding")
        if remediation:
            focus.append(remediation)
        else:
            focus.append(f"Review owner and fix plan for {title}.")
    return focus[:4]


def _fallback_finding_advisory(finding: dict[str, Any]) -> dict[str, Any]:
    severity = str(finding.get("severity", "info"))
    verification_state = str(finding.get("verification_state", "detected"))
    target = str(finding.get("target", "the target"))
    exploitability = str(finding.get("exploitability") or "not yet proven")
    title = str(finding.get("title", "Finding"))
    confidence = int(finding.get("verification_confidence") or finding.get("confidence") or 60)
    remediation = str(finding.get("remediation") or "").strip()

    return {
        "finding_id": finding.get("finding_id"),
        "title": title,
        "why_it_matters": (
            f"{title} affects {target} and currently sits at {severity} severity with "
            f"a {verification_state} verification state."
        ),
        "business_impact": (
            f"If exploited, this issue could expose sensitive functionality or data on {target}, "
            "raising both security and remediation urgency."
        ),
        "exploitability_assessment": (
            f"Exploitability is currently assessed as {exploitability}; proof status is {verification_state}."
        ),
        "triage_priority": _priority_for_finding(severity, verification_state),
        "next_steps": [
            remediation or f"Reproduce and validate {title} with the stored request/response evidence.",
            "Map the issue to the closest exposed endpoint or service owner before assigning the fix.",
        ],
        "confidence": min(max(confidence, 40), 100),
    }


def _priority_for_finding(severity: str, verification_state: str) -> str:
    if verification_state == "verified" and severity in {"critical", "high"}:
        return "immediate"
    if severity == "critical":
        return "high"
    if severity == "high":
        return "high" if verification_state != "detected" else "medium"
    if severity == "medium":
        return "medium"
    return "low"


def _normalize_reasoning_output(
    *,
    raw: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    fallback = _build_fallback_advisory(context)

    attack_raw = raw.get("attack_graph", {}) if isinstance(raw, dict) else {}
    report_raw = raw.get("report", {}) if isinstance(raw, dict) else {}
    findings_raw = raw.get("findings", []) if isinstance(raw, dict) else []

    attack = {
        "summary": _clean_text(attack_raw.get("summary")) or fallback["attack_graph"]["summary"],
        "risk_overview": _clean_text(attack_raw.get("risk_overview"))
        or fallback["attack_graph"]["risk_overview"],
        "next_steps": _normalize_next_steps(
            attack_raw.get("next_steps"),
            fallback["attack_graph"]["next_steps"],
        ),
        "confidence": _normalize_confidence(
            attack_raw.get("confidence"),
            fallback["attack_graph"]["confidence"],
        ),
    }

    report = {
        "draft_summary": _clean_text(report_raw.get("draft_summary"))
        or fallback["report"]["draft_summary"],
        "prioritization_notes": _clean_text(report_raw.get("prioritization_notes"))
        or fallback["report"]["prioritization_notes"],
        "remediation_focus": _normalize_string_list(
            report_raw.get("remediation_focus"),
            fallback["report"]["remediation_focus"],
        ),
        "confidence": _normalize_confidence(
            report_raw.get("confidence"),
            fallback["report"]["confidence"],
        ),
    }

    findings = _normalize_finding_reasoning(
        raw_findings=findings_raw,
        context_findings=context.get("findings", []),
        fallback_findings=fallback["findings"],
    )

    return {
        "attack_graph": attack,
        "report": report,
        "findings": findings,
    }


def _normalize_next_steps(
    raw_steps: Any,
    fallback_steps: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(raw_steps, list):
        return fallback_steps

    normalized: list[dict[str, Any]] = []
    for step in raw_steps[:4]:
        if not isinstance(step, dict):
            continue
        title = _clean_text(step.get("title"))
        rationale = _clean_text(step.get("rationale"))
        if not title or not rationale:
            continue
        normalized.append(
            {
                "title": title,
                "rationale": rationale,
                "confidence": _normalize_confidence(step.get("confidence"), 70),
            }
        )

    return normalized or fallback_steps


def _normalize_finding_reasoning(
    *,
    raw_findings: Any,
    context_findings: list[dict[str, Any]],
    fallback_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(raw_findings, list):
        return fallback_findings

    by_id = {
        str(item.get("finding_id")): item
        for item in context_findings
        if item.get("finding_id")
    }
    by_title = {
        str(item.get("title", "")).strip().lower(): item
        for item in context_findings
        if item.get("title")
    }

    normalized: list[dict[str, Any]] = []
    for candidate in raw_findings[: max(len(context_findings), 1)]:
        if not isinstance(candidate, dict):
            continue

        candidate_id = str(candidate.get("finding_id") or "").strip()
        candidate_title = _clean_text(candidate.get("title"))
        context_item = by_id.get(candidate_id)
        if context_item is None and candidate_title:
            context_item = by_title.get(candidate_title.lower())
        if context_item is None:
            continue

        fallback_item = _fallback_finding_advisory(context_item)
        normalized.append(
            {
                "finding_id": context_item.get("finding_id"),
                "title": candidate_title or fallback_item["title"],
                "why_it_matters": _clean_text(candidate.get("why_it_matters"))
                or fallback_item["why_it_matters"],
                "business_impact": _clean_text(candidate.get("business_impact"))
                or fallback_item["business_impact"],
                "exploitability_assessment": _clean_text(candidate.get("exploitability_assessment"))
                or fallback_item["exploitability_assessment"],
                "triage_priority": _normalize_priority(
                    candidate.get("triage_priority"),
                    fallback_item["triage_priority"],
                ),
                "next_steps": _normalize_string_list(
                    candidate.get("next_steps"),
                    fallback_item["next_steps"],
                ),
                "confidence": _normalize_confidence(
                    candidate.get("confidence"),
                    fallback_item["confidence"],
                ),
            }
        )

    return normalized or fallback_findings


def _normalize_priority(value: Any, fallback: str) -> str:
    if not isinstance(value, str):
        return fallback
    normalized = value.strip().lower()
    if normalized in {"immediate", "high", "medium", "low"}:
        return normalized
    return fallback


def _normalize_string_list(value: Any, fallback: list[str]) -> list[str]:
    if not isinstance(value, list):
        return fallback
    normalized = [text for item in value if (text := _clean_text(item))]
    return normalized[:4] or fallback


def _normalize_confidence(value: Any, fallback: int) -> int:
    if isinstance(value, bool):
        return fallback
    if isinstance(value, (int, float)):
        return int(min(max(value, 0), 100))
    if isinstance(value, str) and value.strip().isdigit():
        return int(min(max(int(value.strip()), 0), 100))
    return fallback


def _clean_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.strip().split())
    return cleaned or None


def _extract_json_payload(raw_text: str) -> dict[str, Any]:
    text = raw_text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3:
            text = "\n".join(lines[1:-1]).strip()

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("Model response did not contain a JSON object.")
        payload = json.loads(text[start : end + 1])

    if not isinstance(payload, dict):
        raise ValueError("Model response JSON must be an object.")
    return payload


async def _load_cached_reasoning(
    *,
    scan_id: uuid.UUID,
    session: AsyncSession,
    context_hash: str,
    advisory_mode: AIAdvisoryMode,
) -> dict[str, Any] | None:
    stmt = (
        select(ScanArtifact)
        .where(
            ScanArtifact.scan_id == scan_id,
            ScanArtifact.artifact_type == _ADVISORY_ARTIFACT_TYPE,
        )
        .order_by(ScanArtifact.created_at.desc())
        .limit(12)
    )
    artifacts = (await session.execute(stmt)).scalars().all()
    for artifact in artifacts:
        metadata = artifact.metadata_ or {}
        if str(metadata.get("context_hash") or "") != context_hash:
            continue
        if _normalize_advisory_mode(metadata.get("advisory_mode")) != advisory_mode:
            continue

        payload = read_json_artifact(artifact.storage_ref)
        if not isinstance(payload, dict):
            continue

        return _build_reasoning_response(
            scan_id=scan_id,
            artifact=artifact,
            payload=payload,
        )

    return None


async def _store_reasoning_artifact(
    *,
    scan: Scan,
    session: AsyncSession,
    context_hash: str,
    context: dict[str, Any],
    run: AIReasoningRun,
) -> ScanArtifact:
    timestamp = run.generated_at.strftime("%Y%m%dT%H%M%S%fZ")
    storage_ref = (
        f"artifacts/{scan.tenant_id}/{scan.id}/advisory/"
        f"ai_reasoning_{run.advisory_mode}_{timestamp}.json"
    )
    payload = _artifact_payload_for_response(
        artifact=None,
        context_hash=context_hash,
        run=run,
        context=context,
    )
    size_bytes, checksum = write_json_artifact(storage_ref, payload)

    artifact = ScanArtifact(
        scan_id=scan.id,
        tenant_id=scan.tenant_id,
        node_id=None,
        artifact_type=_ADVISORY_ARTIFACT_TYPE,
        storage_ref=storage_ref,
        content_type="application/json",
        size_bytes=size_bytes,
        checksum=checksum,
        metadata_=apply_artifact_retention_metadata(
            {
                "tool": "advisory_reasoning",
                "advisory_mode": run.advisory_mode,
                "context_hash": context_hash,
                "prompt_version": run.prompt_version,
                "provider": run.provider,
                "model": run.model,
                "status": run.status,
                "fallback_reason": run.fallback_reason,
                "generated_at": run.generated_at.isoformat(),
                "item_count": len(run.parsed.get("findings", [])),
                "finding_count": len(run.parsed.get("findings", [])),
                "evidence_count": 0,
                "summary": {
                    "provider": run.provider,
                    "model": run.model,
                    "advisory_mode": run.advisory_mode,
                    "status": run.status,
                    "fallback_reason": run.fallback_reason,
                    "finding_count": len(run.parsed.get("findings", [])),
                    "next_step_count": len(
                        run.parsed.get("attack_graph", {}).get("next_steps", [])
                    ),
                },
            },
            policy="advisory",
        ),
    )
    session.add(artifact)
    await session.flush()

    final_payload = _artifact_payload_for_response(
        artifact=artifact,
        context_hash=context_hash,
        run=run,
        context=context,
    )
    final_size_bytes, final_checksum = write_json_artifact(storage_ref, final_payload)
    artifact.size_bytes = final_size_bytes
    artifact.checksum = final_checksum
    await session.flush()
    return artifact


async def _record_reasoning_audit(
    *,
    session: AsyncSession,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    scan_id: uuid.UUID,
    artifact: ScanArtifact,
    run: AIReasoningRun,
    context_hash: str,
) -> None:
    action = "ai_reasoning.generated" if run.status == "generated" else "ai_reasoning.fallback"
    session.add(
        AuditLog(
            tenant_id=tenant_id,
            user_id=user_id,
            action=action,
            resource_type="scan",
            resource_id=str(scan_id),
            details={
                "artifact_id": str(artifact.id),
                "storage_ref": artifact.storage_ref,
                "prompt_version": run.prompt_version,
                "provider": run.provider,
                "model": run.model,
                "advisory_mode": run.advisory_mode,
                "status": run.status,
                "fallback_reason": run.fallback_reason,
                "context_hash": context_hash,
            },
        )
    )
    await session.flush()


def _artifact_payload_for_response(
    *,
    artifact: ScanArtifact | None,
    context_hash: str,
    run: AIReasoningRun,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "version": run.prompt_version,
        "advisory_mode": run.advisory_mode,
        "generated_at": run.generated_at.isoformat(),
        "provider": run.provider,
        "model": run.model,
        "status": run.status,
        "fallback_reason": run.fallback_reason,
        "request": {
            "prompt_version": run.prompt_version,
            "system_prompt": run.system_prompt,
            "user_prompt": run.user_prompt,
            "context_hash": context_hash,
            "input_summary": {
                "scan_id": context.get("scan", {}).get("scan_id") if isinstance(context, dict) else None,
                "asset_target": context.get("scan", {}).get("asset_target") if isinstance(context, dict) else None,
                "finding_count": len(context.get("findings", [])) if isinstance(context, dict) else 0,
                "evidence_count": len(context.get("evidence", [])) if isinstance(context, dict) else 0,
            },
        },
        "response": {
            "raw_text": run.raw_text,
            "parsed": run.parsed,
        },
        "audit": {
            "artifact_id": str(artifact.id) if artifact is not None else None,
            "storage_ref": artifact.storage_ref if artifact is not None else None,
            "context_hash": context_hash,
            "prompt_version": run.prompt_version,
            "prompt_artifact_type": _ADVISORY_ARTIFACT_TYPE,
        },
    }


def _build_reasoning_response(
    *,
    scan_id: uuid.UUID,
    artifact: ScanArtifact,
    payload: dict[str, Any],
) -> dict[str, Any]:
    parsed = payload.get("response", {}).get("parsed", {}) if isinstance(payload, dict) else {}
    audit = payload.get("audit", {}) if isinstance(payload, dict) else {}
    return {
        "scan_id": scan_id,
        "generated_at": payload.get("generated_at") or artifact.created_at,
        "provider": payload.get("provider") or "fallback",
        "model": payload.get("model") or _FALLBACK_MODEL,
        "advisory_mode": payload.get("advisory_mode") or _DEFAULT_ADVISORY_MODE,
        "status": payload.get("status") or "fallback",
        "fallback_reason": payload.get("fallback_reason"),
        "attack_graph": parsed.get("attack_graph", {}),
        "report": parsed.get("report", {}),
        "findings": parsed.get("findings", []),
        "audit": {
            "artifact_id": audit.get("artifact_id") or artifact.id,
            "storage_ref": audit.get("storage_ref") or artifact.storage_ref,
            "context_hash": audit.get("context_hash") or artifact.metadata_.get("context_hash", ""),
            "prompt_version": audit.get("prompt_version") or artifact.metadata_.get("prompt_version") or _prompt_version_for_mode(_normalize_advisory_mode(payload.get("advisory_mode"))),
            "prompt_artifact_type": audit.get("prompt_artifact_type") or _ADVISORY_ARTIFACT_TYPE,
        },
    }


def _truncate(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.strip().split())
    if len(cleaned) <= limit:
        return cleaned
    return f"{cleaned[: limit - 3]}..."


# ═══════════════════════════════════════════════════════════════════════
#  Phase 5 — AI-Driven Intelligence Methods
# ═══════════════════════════════════════════════════════════════════════

_EXPLOITATION_PATHS_PROMPT = """You are Pentra Offensive AI Advisor.

Analyze the provided scan findings and attack graph to suggest exploitation paths.

For each path, provide:
1. A step-by-step attack chain (ordered exploitation steps)
2. The impact if the chain succeeds (data breach, RCE, privilege escalation, etc.)
3. Likelihood assessment (high/medium/low) based on evidence quality
4. MITRE ATT&CK technique IDs for each step
5. Required tools and conditions for each step
6. Estimated difficulty (trivial/moderate/difficult/expert)

Return valid JSON only:
{
  "exploitation_paths": [
    {
      "id": "path-1",
      "name": "string",
      "chain": [
        {
          "step": 1,
          "action": "string",
          "finding_id": "uuid-or-null",
          "tool": "string",
          "mitre_technique": "T1190",
          "prereqs": ["string"]
        }
      ],
      "impact": "string",
      "likelihood": "high|medium|low",
      "difficulty": "trivial|moderate|difficult|expert",
      "business_risk": "string",
      "evidence_quality": "confirmed|probable|theoretical"
    }
  ],
  "cross_finding_patterns": [
    {
      "pattern": "string",
      "related_findings": ["uuid"],
      "combined_severity": "critical|high|medium|low",
      "recommendation": "string"
    }
  ],
  "lateral_movement_opportunities": [
    {
      "from": "string",
      "to": "string",
      "technique": "string",
      "mitre_id": "T1021"
    }
  ],
  "overall_risk_score": 0,
  "confidence": 0
}
"""

_VECTOR_PRIORITIZATION_PROMPT = """You are Pentra Attack Vector Prioritizer.

Given the scan findings, target profile, and available attack vectors, rank which
attack vectors should be tested next and in what order.

Consider:
1. Already-confirmed vulnerabilities that enable further testing
2. Target technology stack (detected frameworks, services, APIs)
3. Attack surface breadth (number of endpoints, subdomains, services)
4. Historical success rate of each vector against similar targets
5. Risk-to-effort ratio for the pentest team

Return valid JSON only:
{
  "prioritized_vectors": [
    {
      "vector_id": "string",
      "name": "string",
      "priority": 1,
      "rationale": "string",
      "estimated_success_probability": 0.0,
      "required_tools": ["string"],
      "depends_on_findings": ["uuid"],
      "estimated_time_minutes": 0
    }
  ],
  "recommended_tool_sequence": ["tool_id_1", "tool_id_2"],
  "skip_vectors": [
    {
      "vector_id": "string",
      "reason": "string"
    }
  ],
  "confidence": 0
}
"""

_REMEDIATION_REPORT_PROMPT = """You are Pentra Remediation Advisor.

Generate actionable remediation recommendations for the provided scan findings.
Group by priority and provide specific fix instructions.

For each finding:
1. Root cause analysis
2. Specific fix instructions (code-level when possible)
3. Verification steps to confirm the fix
4. Related CWE and compliance frameworks (PCI-DSS, SOC2, HIPAA, GDPR)
5. Estimated remediation effort (hours)
6. Quick win vs long-term fix distinction

Return valid JSON only:
{
  "executive_summary": "string",
  "overall_risk_rating": "critical|high|medium|low",
  "remediation_items": [
    {
      "finding_id": "uuid-or-null",
      "title": "string",
      "severity": "critical|high|medium|low",
      "root_cause": "string",
      "fix_instructions": ["string"],
      "quick_win": "string or null",
      "long_term_fix": "string",
      "verification_steps": ["string"],
      "estimated_hours": 0,
      "cwe_id": "CWE-XXX",
      "compliance_impact": ["PCI-DSS 6.5.1", "SOC2 CC6.1"]
    }
  ],
  "grouped_recommendations": [
    {
      "group": "string",
      "description": "string",
      "items": ["finding_id"],
      "shared_fix": "string"
    }
  ],
  "priority_order": ["finding_id_1", "finding_id_2"],
  "total_estimated_hours": 0,
  "confidence": 0
}
"""

_REALTIME_TOOL_ANALYSIS_PROMPT = """You are Pentra Real-Time Intelligence Engine.

A security tool just completed execution during a live scan. Analyze its output
and provide immediate intelligence:

1. Key findings extracted from the tool output
2. Whether additional tools should run based on discoveries
3. Attack vector implications of the results
4. Severity assessment of any discovered issues

Return valid JSON only:
{
  "key_discoveries": [
    {
      "type": "string",
      "detail": "string",
      "severity": "critical|high|medium|low|info",
      "confidence": 0
    }
  ],
  "suggested_next_tools": [
    {
      "tool_id": "string",
      "reason": "string",
      "priority": "immediate|next|optional"
    }
  ],
  "attack_surface_updates": [
    {
      "type": "new_endpoint|new_service|new_technology|credential_found",
      "detail": "string"
    }
  ],
  "risk_indicators": ["string"],
  "confidence": 0
}
"""


async def suggest_exploitation_paths(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    session: AsyncSession,
) -> dict[str, Any]:
    """Analyze findings and suggest exploitation chains with MITRE mapping.

    Uses AI to connect individual findings into credible multi-step attack
    chains, assess lateral movement opportunities, and identify cross-finding
    patterns that indicate systemic weaknesses.
    """
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id, Scan.tenant_id == tenant_id)
        .options(selectinload(Scan.asset), selectinload(Scan.findings))
    )
    scan = (await session.execute(stmt)).scalar_one_or_none()
    if scan is None:
        return {"error": "Scan not found"}

    graph = await scan_service.get_attack_graph(
        scan_id=scan_id, tenant_id=tenant_id, session=session,
    )
    evidence = await scan_service.list_evidence_references(
        scan_id=scan_id, tenant_id=tenant_id, session=session,
    )

    context = _build_reasoning_context(
        scan=scan, graph=graph, report=None,
        evidence=evidence, advisory_mode=_DEEP_ADVISORY_MODE,
    )

    system_prompt = _EXPLOITATION_PATHS_PROMPT
    user_prompt = (
        "Analyze these scan results and suggest exploitation paths.\n\n"
        f"Context JSON:\n{json.dumps(context, indent=2, sort_keys=True, default=str)}"
    )

    await _release_read_transaction(session)
    result = await _run_specialized_prompt(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        advisory_mode=_DEEP_ADVISORY_MODE,
        fallback_key="exploitation_paths",
    )

    # If AI couldn't run, generate deterministic exploitation paths
    if result.get("_is_fallback"):
        result = _build_deterministic_exploitation_paths(context)

    return {
        "scan_id": str(scan_id),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **result,
    }


async def prioritize_attack_vectors(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    session: AsyncSession,
    available_vectors: list[str] | None = None,
) -> dict[str, Any]:
    """Rank attack vectors by likelihood and impact for the target.

    AI evaluates the target's technology stack, discovered endpoints, and
    existing findings to determine which attack vectors to test next and
    in what order, optimizing the pentester's time.
    """
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id, Scan.tenant_id == tenant_id)
        .options(selectinload(Scan.asset), selectinload(Scan.findings))
    )
    scan = (await session.execute(stmt)).scalar_one_or_none()
    if scan is None:
        return {"error": "Scan not found"}

    context = _build_reasoning_context(
        scan=scan, graph=None, report=None,
        evidence=[], advisory_mode=_DEFAULT_ADVISORY_MODE,
    )

    if available_vectors:
        context["available_vectors"] = available_vectors

    system_prompt = _VECTOR_PRIORITIZATION_PROMPT
    user_prompt = (
        "Prioritize attack vectors for this target based on scan results.\n\n"
        f"Context JSON:\n{json.dumps(context, indent=2, sort_keys=True, default=str)}"
    )

    await _release_read_transaction(session)
    result = await _run_specialized_prompt(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        advisory_mode=_DEFAULT_ADVISORY_MODE,
        fallback_key="prioritized_vectors",
    )

    if result.get("_is_fallback"):
        result = _build_deterministic_vector_priorities(context, available_vectors)

    return {
        "scan_id": str(scan_id),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **result,
    }


async def generate_remediation_report(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    session: AsyncSession,
) -> dict[str, Any]:
    """Generate actionable remediation recommendations for scan findings.

    Produces grouped fix instructions with effort estimates, compliance
    mapping, quick wins, and verification steps. Groups related findings
    for efficient batch remediation.
    """
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id, Scan.tenant_id == tenant_id)
        .options(selectinload(Scan.asset), selectinload(Scan.findings))
    )
    scan = (await session.execute(stmt)).scalar_one_or_none()
    if scan is None:
        return {"error": "Scan not found"}

    report = await scan_service.get_scan_report(
        scan_id=scan_id, tenant_id=tenant_id, session=session,
    )
    context = _build_reasoning_context(
        scan=scan, graph=None, report=report,
        evidence=[], advisory_mode=_DEEP_ADVISORY_MODE,
    )

    system_prompt = _REMEDIATION_REPORT_PROMPT
    user_prompt = (
        "Generate a remediation report with actionable fix instructions.\n\n"
        f"Context JSON:\n{json.dumps(context, indent=2, sort_keys=True, default=str)}"
    )

    await _release_read_transaction(session)
    result = await _run_specialized_prompt(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        advisory_mode=_DEEP_ADVISORY_MODE,
        fallback_key="remediation_items",
    )

    if result.get("_is_fallback"):
        result = _build_deterministic_remediation(context)

    return {
        "scan_id": str(scan_id),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **result,
    }


async def analyze_tool_output_realtime(
    *,
    tool_id: str,
    tool_output: str,
    scan_context: dict[str, Any],
) -> dict[str, Any]:
    """Analyze a tool's output in real-time during an active scan.

    Called by the orchestrator after each tool completes. Returns
    intelligence about discoveries, suggested follow-up tools, and
    attack surface updates without blocking the scan pipeline.
    """
    context = {
        "tool_id": tool_id,
        "tool_output_preview": tool_output[:4000],  # Limit context size
        "scan_type": scan_context.get("scan_type", "unknown"),
        "asset_target": scan_context.get("asset_target", "unknown"),
        "findings_so_far": scan_context.get("findings_count", 0),
    }

    system_prompt = _REALTIME_TOOL_ANALYSIS_PROMPT
    user_prompt = (
        f"A '{tool_id}' tool just completed during a live scan. "
        "Analyze the output and provide real-time intelligence.\n\n"
        f"Context JSON:\n{json.dumps(context, indent=2, default=str)}"
    )

    result = await _run_specialized_prompt(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        advisory_mode=_DEFAULT_ADVISORY_MODE,
        fallback_key="key_discoveries",
    )

    if result.get("_is_fallback"):
        result = _build_deterministic_tool_analysis(tool_id, tool_output)

    return {
        "tool_id": tool_id,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        **result,
    }


# ── Shared prompt execution ─────────────────────────────────────────

async def _run_specialized_prompt(
    *,
    system_prompt: str,
    user_prompt: str,
    advisory_mode: AIAdvisoryMode,
    fallback_key: str,
) -> dict[str, Any]:
    """Execute a specialized prompt through the provider chain."""
    if not settings.ai_reasoning_enabled:
        return {"_is_fallback": True}

    for provider in _provider_chain_from_settings():
        config = AIReasoningConfig.from_settings(provider, advisory_mode)
        if config.requires_api_key and not config.api_key.strip():
            continue

        try:
            client = _build_provider_client(config)
            # Build a minimal context for the client
            run = AIReasoningRun(
                generated_at=datetime.now(timezone.utc),
                provider=config.provider,
                model=config.model,
                advisory_mode=advisory_mode,
                prompt_version=_prompt_version_for_mode(advisory_mode),
                status="pending",
                fallback_reason=None,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                raw_text="",
                parsed={},
            )

            # Call the API directly
            client = _build_provider_client(config)
            if config.request_surface == "openai_responses":
                raw_text = await OpenAIReasoningClient(config)._call_responses_api(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                )
            elif config.request_surface == "openai_chat_completions":
                raw_text = await OpenAICompatibleReasoningClient(config)._call_chat_completions_api(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                )
            else:
                raw_text = await AnthropicReasoningClient(config)._call_messages_api(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                )

            parsed = _extract_json_payload(raw_text)
            if isinstance(parsed, dict) and parsed.get(fallback_key):
                return parsed

        except Exception as exc:
            logger.warning("Specialized prompt failed via %s: %s", provider, exc)
            continue

    return {"_is_fallback": True}


# ── Deterministic fallbacks ──────────────────────────────────────────

def _build_deterministic_exploitation_paths(
    context: dict[str, Any],
) -> dict[str, Any]:
    """Build exploitation paths without AI, using finding severity and type."""
    findings = context.get("findings", [])
    paths = []

    # Group critical/high findings into potential chains
    critical_findings = [f for f in findings if f.get("severity") in ("critical", "high")]
    if critical_findings:
        chain = []
        for i, finding in enumerate(critical_findings[:4]):
            chain.append({
                "step": i + 1,
                "action": f"Exploit {finding.get('title', 'finding')}",
                "finding_id": finding.get("finding_id"),
                "tool": finding.get("tool_source", "unknown"),
                "mitre_technique": "T1190",
                "prereqs": [] if i == 0 else [f"Step {i}"],
            })

        paths.append({
            "id": "path-1",
            "name": "Primary exploitation chain via critical findings",
            "chain": chain,
            "impact": "Potential full system compromise via chained critical vulnerabilities",
            "likelihood": "high" if any(f.get("verification_state") == "verified" for f in critical_findings) else "medium",
            "difficulty": "moderate",
            "business_risk": f"{len(critical_findings)} critical/high findings affect {context.get('scan', {}).get('asset_target', 'target')}",
            "evidence_quality": "confirmed" if any(f.get("verification_state") == "verified" for f in critical_findings) else "probable",
        })

    return {
        "exploitation_paths": paths,
        "cross_finding_patterns": [],
        "lateral_movement_opportunities": [],
        "overall_risk_score": min(len(critical_findings) * 20, 100) if critical_findings else 20,
        "confidence": 65,
    }


def _build_deterministic_vector_priorities(
    context: dict[str, Any],
    available_vectors: list[str] | None,
) -> dict[str, Any]:
    """Prioritize vectors deterministically by severity frequency."""
    findings = context.get("findings", [])
    severity_scores = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}

    # Default vector priority based on general effectiveness
    default_vectors = [
        ("sqli", "SQL Injection", 90, ["sqlmap", "nuclei"]),
        ("xss_reflected", "Reflected XSS", 85, ["dalfox", "nuclei"]),
        ("command_injection", "Command Injection", 95, ["nuclei"]),
        ("ssrf", "Server-Side Request Forgery", 80, ["nuclei"]),
        ("broken_auth", "Broken Authentication", 88, ["nuclei", "web_interact"]),
        ("path_traversal", "Path Traversal", 75, ["nuclei", "ffuf"]),
        ("cors_misconfig", "CORS Misconfiguration", 70, ["cors_scanner"]),
        ("jwt_none_algo", "JWT None Algorithm", 85, ["jwt_tool"]),
        ("graphql_introspection", "GraphQL Introspection", 65, ["graphql_cop"]),
    ]

    prioritized = []
    for i, (vid, name, score, tools) in enumerate(default_vectors):
        if available_vectors and vid not in available_vectors:
            continue
        prioritized.append({
            "vector_id": vid,
            "name": name,
            "priority": i + 1,
            "rationale": f"Standard priority based on general effectiveness and target type",
            "estimated_success_probability": score / 100.0,
            "required_tools": tools,
            "depends_on_findings": [],
            "estimated_time_minutes": 15,
        })

    return {
        "prioritized_vectors": prioritized,
        "recommended_tool_sequence": ["nuclei", "sqlmap", "dalfox", "ffuf", "jwt_tool"],
        "skip_vectors": [],
        "confidence": 60,
    }


def _build_deterministic_remediation(
    context: dict[str, Any],
) -> dict[str, Any]:
    """Build remediation report without AI."""
    findings = context.get("findings", [])
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 4))

    items = []
    total_hours = 0
    for finding in sorted_findings[:8]:
        severity = finding.get("severity", "info")
        title = finding.get("title", "Finding")
        remediation = finding.get("remediation") or ""
        hours = {"critical": 8, "high": 4, "medium": 2, "low": 1, "info": 0.5}.get(severity, 2)
        total_hours += hours

        items.append({
            "finding_id": finding.get("finding_id"),
            "title": title,
            "severity": severity,
            "root_cause": f"Vulnerability detected in {finding.get('target', 'target')}",
            "fix_instructions": [remediation] if remediation else [f"Review and remediate {title}"],
            "quick_win": f"Add input validation/sanitization for {title}" if severity in ("critical", "high") else None,
            "long_term_fix": f"Implement defense-in-depth controls for {title}",
            "verification_steps": [f"Re-run scan to verify {title} is resolved"],
            "estimated_hours": hours,
            "cwe_id": "",
            "compliance_impact": [],
        })

    critical_count = sum(1 for f in findings if f.get("severity") == "critical")
    high_count = sum(1 for f in findings if f.get("severity") == "high")

    return {
        "executive_summary": (
            f"Scan identified {len(findings)} findings ({critical_count} critical, "
            f"{high_count} high). Immediate attention required for critical issues."
        ),
        "overall_risk_rating": "critical" if critical_count else ("high" if high_count else "medium"),
        "remediation_items": items,
        "grouped_recommendations": [],
        "priority_order": [f.get("finding_id") for f in sorted_findings[:8] if f.get("finding_id")],
        "total_estimated_hours": total_hours,
        "confidence": 70,
    }


def _build_deterministic_tool_analysis(
    tool_id: str,
    tool_output: str,
) -> dict[str, Any]:
    """Extract basic intelligence from tool output without AI."""
    discoveries = []
    output_lower = tool_output.lower()

    # Pattern-based extraction
    severity_patterns = {
        "critical": ["rce", "remote code execution", "sql injection", "command injection"],
        "high": ["xss", "cross-site", "path traversal", "lfi", "ssrf", "xxe"],
        "medium": ["cors", "open redirect", "csrf", "missing header"],
        "low": ["information disclosure", "directory listing", "verbose error"],
    }

    for severity, patterns in severity_patterns.items():
        for pattern in patterns:
            if pattern in output_lower:
                discoveries.append({
                    "type": pattern.replace(" ", "_"),
                    "detail": f"Detected {pattern} indicator in {tool_id} output",
                    "severity": severity,
                    "confidence": 70,
                })

    # Suggest follow-up tools based on what was found
    suggested = []
    if any(d["severity"] in ("critical", "high") for d in discoveries):
        if tool_id not in ("sqlmap",):
            suggested.append({
                "tool_id": "sqlmap",
                "reason": "High-severity finding detected, verify with dedicated scanner",
                "priority": "immediate",
            })
        if tool_id not in ("nuclei",):
            suggested.append({
                "tool_id": "nuclei",
                "reason": "Run targeted templates against discovered vulnerabilities",
                "priority": "next",
            })

    return {
        "key_discoveries": discoveries or [{
            "type": "scan_complete",
            "detail": f"{tool_id} completed without notable findings",
            "severity": "info",
            "confidence": 90,
        }],
        "suggested_next_tools": suggested,
        "attack_surface_updates": [],
        "risk_indicators": [d["detail"] for d in discoveries if d["severity"] in ("critical", "high")],
        "confidence": 65 if discoveries else 85,
    }
