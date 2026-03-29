"""Shared AI provider routing for Pentra services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pentra_common.config.settings import Settings

AIProviderName = Literal["anthropic", "openai", "groq", "ollama", "gemini"]
AITaskType = Literal["advisory", "strategy"]
AIModelTier = Literal["default", "deep"]
AIRequestSurface = Literal[
    "anthropic_messages",
    "openai_responses",
    "openai_chat_completions",
]

_OPENAI_COMPATIBLE_PROVIDERS = {"openai", "groq", "ollama", "gemini"}


@dataclass(frozen=True)
class ProviderRoutingOverride:
    """Optional runtime override used by services or smoke scripts."""

    provider: AIProviderName | None = None
    api_key: str = ""
    model: str = ""
    base_url: str = ""


@dataclass(frozen=True)
class ResolvedAIProvider:
    """Concrete provider configuration for one task and model tier."""

    provider: AIProviderName
    task_type: AITaskType
    model_tier: AIModelTier
    model: str
    api_key: str
    base_url: str
    request_surface: AIRequestSurface
    requires_api_key: bool = True
    anthropic_version: str | None = None
    reasoning_effort: str | None = None


def normalize_provider(provider: str | None) -> AIProviderName | None:
    normalized = str(provider or "").strip().lower()
    if normalized == "anthropic":
        return "anthropic"
    if normalized in {"openai", "openrouter"}:
        return "openai"
    if normalized == "groq":
        return "groq"
    if normalized == "ollama":
        return "ollama"
    if normalized == "gemini":
        return "gemini"
    return None


def provider_priority_from_settings(
    settings: Settings,
    *,
    override_provider: str | None = None,
    primary_fallback_only: bool = False,
) -> list[AIProviderName]:
    explicit_override = normalize_provider(override_provider)
    if explicit_override is not None:
        return [explicit_override]

    candidates: list[str] = []
    if settings.ai_provider_priority.strip():
        raw_priority = settings.ai_provider_priority.split(",")
        if primary_fallback_only:
            candidates.extend(raw_priority[:2])
        else:
            candidates.extend(raw_priority)
    else:
        candidates.extend(
            [
                settings.ai_reasoning_primary_provider,
                settings.ai_reasoning_fallback_provider,
            ]
        )
        if not primary_fallback_only and settings.ai_reasoning_additional_providers.strip():
            candidates.extend(settings.ai_reasoning_additional_providers.split(","))

    ordered: list[AIProviderName] = []
    for candidate in candidates:
        normalized = normalize_provider(candidate)
        if normalized and normalized not in ordered:
            ordered.append(normalized)

    return ordered or ["anthropic", "openai"]


def resolve_provider_chain(
    settings: Settings,
    *,
    task_type: AITaskType,
    model_tier: AIModelTier = "default",
    override: ProviderRoutingOverride | None = None,
    primary_fallback_only: bool = False,
) -> list[ResolvedAIProvider]:
    configs: list[ResolvedAIProvider] = []
    order = provider_priority_from_settings(
        settings,
        override_provider=override.provider if override else None,
        primary_fallback_only=primary_fallback_only,
    )
    for provider in order:
        config = resolve_provider_config(
            settings,
            provider=provider,
            task_type=task_type,
            model_tier=model_tier,
            override=override if override and override.provider == provider else None,
        )
        if config is not None:
            configs.append(config)
    return configs


def resolve_provider_config(
    settings: Settings,
    *,
    provider: str,
    task_type: AITaskType,
    model_tier: AIModelTier = "default",
    override: ProviderRoutingOverride | None = None,
) -> ResolvedAIProvider | None:
    normalized = normalize_provider(provider)
    if normalized is None:
        return None

    if normalized == "anthropic":
        model = _coalesce(
            override.model if override else "",
            settings.anthropic_deep_model if model_tier == "deep" else "",
            settings.anthropic_default_model,
            settings.anthropic_model,
        )
        base_url = _coalesce(
            override.base_url if override else "",
            settings.anthropic_base_url,
        )
        api_key = _coalesce(
            override.api_key if override else "",
            settings.anthropic_api_key,
        )
        if not model or not base_url or not api_key:
            return None
        return ResolvedAIProvider(
            provider="anthropic",
            task_type=task_type,
            model_tier=model_tier,
            model=model,
            api_key=api_key,
            base_url=base_url.rstrip("/"),
            request_surface="anthropic_messages",
            anthropic_version=settings.anthropic_version,
        )

    if normalized not in _OPENAI_COMPATIBLE_PROVIDERS:
        return None

    model = _coalesce(
        override.model if override else "",
        _provider_model(settings, normalized, model_tier),
    )
    base_url = _coalesce(
        override.base_url if override else "",
        _provider_base_url(settings, normalized),
    )
    api_key = _coalesce(
        override.api_key if override else "",
        _provider_api_key(settings, normalized),
    )
    requires_api_key = normalized != "ollama"

    if not model or not base_url:
        return None
    if requires_api_key and not api_key:
        return None

    request_surface: AIRequestSurface = "openai_chat_completions"
    if normalized == "openai" and task_type == "advisory":
        request_surface = "openai_responses"

    reasoning_effort: str | None = None
    if normalized == "openai" and task_type == "advisory":
        reasoning_effort = _coalesce(
            settings.openai_deep_reasoning_effort
            if model_tier == "deep"
            else settings.openai_standard_reasoning_effort,
        ) or None

    return ResolvedAIProvider(
        provider=normalized,
        task_type=task_type,
        model_tier=model_tier,
        model=model,
        api_key=api_key,
        base_url=base_url.rstrip("/"),
        request_surface=request_surface,
        requires_api_key=requires_api_key,
        reasoning_effort=reasoning_effort,
    )


def _provider_model(
    settings: Settings,
    provider: AIProviderName,
    model_tier: AIModelTier,
) -> str:
    if provider == "openai":
        return (
            settings.openai_deep_model
            if model_tier == "deep"
            else settings.openai_default_model
        )
    if provider == "groq":
        return (
            settings.groq_deep_model
            if model_tier == "deep"
            else settings.groq_default_model
        )
    if provider == "ollama":
        return (
            settings.ollama_deep_model
            if model_tier == "deep"
            else settings.ollama_default_model
        )
    if provider == "gemini":
        return (
            settings.gemini_deep_model
            if model_tier == "deep"
            else settings.gemini_default_model
        )
    return ""


def _provider_base_url(settings: Settings, provider: AIProviderName) -> str:
    if provider == "openai":
        return settings.openai_base_url
    if provider == "groq":
        return settings.groq_base_url
    if provider == "ollama":
        return settings.ollama_base_url
    if provider == "gemini":
        return settings.gemini_base_url
    return ""


def _provider_api_key(settings: Settings, provider: AIProviderName) -> str:
    if provider == "openai":
        return settings.openai_api_key
    if provider == "groq":
        return settings.groq_api_key
    if provider == "ollama":
        return settings.ollama_api_key
    if provider == "gemini":
        return settings.gemini_api_key
    return ""


def _coalesce(*values: str) -> str:
    for value in values:
        normalized = str(value or "").strip()
        if normalized:
            return normalized
    return ""
