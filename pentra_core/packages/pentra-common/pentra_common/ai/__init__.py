"""Shared AI routing and prompt-contract helpers for Pentra.

Keep provider-router imports lazy so lightweight helpers like prompt contracts
remain usable in minimal subprocess environments that do not ship the full AI
provider dependency stack.
"""

from __future__ import annotations

from typing import Any

from .prompt_contracts import (
    PromptContract,
    advisory_prompt_contract,
    build_json_user_prompt,
    strategy_prompt_contract,
)
from .bounded_agent import (
    BoundedAgentClient,
    BoundedAgentRequest,
    BoundedAgentResponse,
    pack_context_bundle,
    render_context_bundle,
)

__all__ = [
    "BoundedAgentClient",
    "BoundedAgentRequest",
    "BoundedAgentResponse",
    "PromptContract",
    "ProviderRoutingOverride",
    "ResolvedAIProvider",
    "advisory_prompt_contract",
    "build_json_user_prompt",
    "normalize_provider",
    "pack_context_bundle",
    "provider_priority_from_settings",
    "render_context_bundle",
    "resolve_provider_chain",
    "resolve_provider_config",
    "strategy_prompt_contract",
]


def __getattr__(name: str) -> Any:
    if name in {
        "ProviderRoutingOverride",
        "ResolvedAIProvider",
        "normalize_provider",
        "provider_priority_from_settings",
        "resolve_provider_chain",
        "resolve_provider_config",
    }:
        from . import provider_router as _provider_router

        value = getattr(_provider_router, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module 'pentra_common.ai' has no attribute {name!r}")
