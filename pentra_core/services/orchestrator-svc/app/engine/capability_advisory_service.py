"""Capability-pack advisory execution for planner-side AI ranking."""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

from pentra_common.ai.bounded_agent import (
    BoundedAgentClient,
    BoundedAgentRequest,
    BoundedAgentResponse,
    pack_context_bundle,
    render_context_bundle,
)
from pentra_common.ai.provider_router import (
    ProviderRoutingOverride,
    ResolvedAIProvider,
    normalize_provider,
    resolve_provider_chain,
)
from pentra_common.config.settings import Settings, get_settings
from pentra_common.schemas.capability import CapabilityAdvisoryRequest, CapabilityAdvisoryResponse
from pentra_common.storage.artifacts import read_json_artifact

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are Pentra capability advisory.

You are advisory only. You are helping a planner prioritize follow-up work for
an offensive-security capability pack.

Hard rules:
- Do not certify findings, proof, or exploitation.
- Do not invent evidence that is not present in the supplied context.
- Return valid JSON only.
- Focus on ranking, parameter hypotheses, workflow segmentation, and evidence-gap closure.

Return this JSON object:
{
  "focus_items": [
    {"route_group": "string", "priority": 0, "reason": "string"}
  ],
  "evidence_gap_priorities": ["string"],
  "parameter_hypotheses": ["string"],
  "workflow_segments": [
    {"label": "string", "reason": "string"}
  ],
  "target_profile_hints": [
    {"key": "string", "confidence": 0, "reason": "string"}
  ]
}
"""


class CapabilityAdvisoryService:
    """Execute advisory-only model calls for capability-pack contexts."""

    def __init__(
        self,
        *,
        provider: str = "",
        api_key: str = "",
        model: str = "",
        settings: Settings | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._client = BoundedAgentClient()
        self._provider_override = normalize_provider(provider or os.getenv("AI_PROVIDER", ""))
        self._api_key_override = api_key.strip()
        self._model_override = (model or os.getenv("AI_MODEL", "")).strip()
        self._openai_base_override = (
            os.getenv("OPENAI_API_BASE", "").strip()
            or os.getenv("OPENAI_BASE_URL", "").strip()
        )

    async def recommend_from_artifact_refs(
        self,
        *,
        artifact_refs: list[dict[str, str]],
        target_model_summary: dict[str, Any],
    ) -> list[CapabilityAdvisoryResponse]:
        responses: list[CapabilityAdvisoryResponse] = []
        for request in self._requests_from_artifact_refs(artifact_refs):
            responses.append(
                await self._recommend_for_request(
                    request=request,
                    target_model_summary=target_model_summary,
                )
            )
        return responses

    def _requests_from_artifact_refs(
        self,
        artifact_refs: list[dict[str, str]],
    ) -> list[CapabilityAdvisoryRequest]:
        requests: list[CapabilityAdvisoryRequest] = []
        for item in artifact_refs:
            storage_ref = str(item.get("storage_ref") or "").strip()
            pack_key = str(item.get("pack_key") or "").strip()
            if not storage_ref or not pack_key:
                continue
            payload = read_json_artifact(storage_ref)
            if not isinstance(payload, dict):
                continue
            capability = _extract_capability_summary(payload=payload, pack_key=pack_key)
            advisory_context = _extract_advisory_context(capability)
            if not capability or not advisory_context:
                continue
            prompt_contract = advisory_context.get("prompt_contract") or {}
            user_prompt = str(advisory_context.get("user_prompt") or "").strip()
            if not user_prompt:
                continue
            requests.append(
                CapabilityAdvisoryRequest(
                    pack_key=pack_key,
                    advisory_mode=str(advisory_context.get("advisory_mode") or item.get("advisory_mode") or ""),
                    prompt_contract_id=str(prompt_contract.get("contract_id") or "pentra.ai.advisory"),
                    user_prompt=user_prompt,
                    context=advisory_context,
                    target_profile_keys=_string_list(capability.get("target_profile_keys")),
                    benchmark_target_keys=_string_list(capability.get("benchmark_target_keys")),
                )
            )
        return requests

    async def _recommend_for_request(
        self,
        *,
        request: CapabilityAdvisoryRequest,
        target_model_summary: dict[str, Any],
    ) -> CapabilityAdvisoryResponse:
        start = time.monotonic()
        user_message = self._build_user_message(
            request=request,
            target_model_summary=target_model_summary,
        )
        failures: list[str] = []
        for provider_config in self._provider_configs():
            try:
                bounded_response = await self._call_provider(
                    provider_config,
                    user_message=user_message,
                )
                response = self._parse_response(
                    request=request,
                    raw=bounded_response.output_text,
                    duration_ms=int((time.monotonic() - start) * 1000),
                    provider=provider_config.provider,
                    model=provider_config.model,
                    transport=bounded_response.transport,
                    prompt_version=str(
                        ((request.context.get("prompt_contract") or {}).get("prompt_version") or "")
                    ),
                )
                response.raw_response = bounded_response.output_text
                return response
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{provider_config.provider}: {exc}")
                logger.warning(
                    "Capability advisory provider %s failed for pack %s: %s",
                    provider_config.provider,
                    request.pack_key,
                    exc,
                )

        fallback = self._heuristic_recommend(
            request=request,
            target_model_summary=target_model_summary,
            duration_ms=int((time.monotonic() - start) * 1000),
        )
        if failures:
            fallback.error = " | ".join(failures)
        return fallback

    def _build_user_message(
        self,
        *,
        request: CapabilityAdvisoryRequest,
        target_model_summary: dict[str, Any],
    ) -> str:
        focus_context = pack_context_bundle(
            ("target_profile_hypotheses", target_model_summary.get("target_profile_hypotheses")),
            (
                "planner_context",
                {
                    "top_focus": target_model_summary.get("top_focus"),
                    "capability_pressures": target_model_summary.get("capability_pressures"),
                },
            ),
            ("recent_transcript_entries", target_model_summary.get("recent_transcript_entries")),
            ("recent_jobs", target_model_summary.get("recent_jobs")),
            ("pack_advisory_context", request.context),
            ("knowledge_source_summaries", request.context.get("knowledge_source_summaries")),
            (
                "field_validation_execution_contract",
                target_model_summary.get("field_validation_execution_contract"),
            ),
        )
        return (
            f"{request.user_prompt}\n\n"
            f"Context Bundle JSON:\n{render_context_bundle(focus_context)}"
        )

    def _provider_configs(self) -> list[ResolvedAIProvider]:
        override = ProviderRoutingOverride(
            provider=self._provider_override,
            api_key=self._resolve_override_api_key(),
            model=self._model_override,
            base_url=self._openai_base_override,
        )
        return resolve_provider_chain(
            self._settings,
            task_type="advisory",
            model_tier="default",
            override=override if override.provider is not None else None,
            primary_fallback_only=True,
        )

    def _resolve_override_api_key(self) -> str:
        if self._api_key_override:
            return self._api_key_override
        if self._provider_override is None:
            return ""
        generic = os.getenv("AI_API_KEY", "").strip()
        if generic:
            return generic
        if self._provider_override == "openai":
            return os.getenv("OPENAI_API_KEY", "").strip()
        if self._provider_override == "anthropic":
            return os.getenv("ANTHROPIC_API_KEY", "").strip()
        if self._provider_override == "groq":
            return os.getenv("GROQ_API_KEY", "").strip()
        if self._provider_override == "gemini":
            return os.getenv("GEMINI_API_KEY", "").strip()
        if self._provider_override == "ollama":
            return os.getenv("OLLAMA_API_KEY", "").strip()
        return ""

    async def _call_provider(
        self,
        provider_config: ResolvedAIProvider,
        *,
        user_message: str,
    ) -> BoundedAgentResponse:
        return await self._client.generate(
            BoundedAgentRequest(
                provider=provider_config.provider,
                task_type="advisory",
                model=provider_config.model,
                api_key=provider_config.api_key,
                base_url=provider_config.base_url,
                request_surface=provider_config.request_surface,
                system_prompt=_SYSTEM_PROMPT,
                user_prompt=user_message,
                prompt_contract="pentra.ai.advisory",
                context_bundle={"user_message": user_message},
                anthropic_version=provider_config.anthropic_version,
                reasoning_effort=provider_config.reasoning_effort,
                timeout_seconds=60.0,
                max_tokens=1400,
                temperature=0.0,
            )
        )

    def _parse_response(
        self,
        *,
        request: CapabilityAdvisoryRequest,
        raw: str,
        duration_ms: int,
        provider: str,
        model: str,
        transport: str | None,
        prompt_version: str,
    ) -> CapabilityAdvisoryResponse:
        json_str = raw
        if "```json" in raw:
            json_str = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            json_str = raw.split("```")[1].split("```")[0].strip()
        data = json.loads(json_str)
        return CapabilityAdvisoryResponse(
            pack_key=request.pack_key,
            advisory_mode=request.advisory_mode,
            focus_items=list(data.get("focus_items") or []),
            evidence_gap_priorities=_string_list(data.get("evidence_gap_priorities")),
            parameter_hypotheses=_string_list(data.get("parameter_hypotheses")),
            workflow_segments=list(data.get("workflow_segments") or []),
            target_profile_hints=list(data.get("target_profile_hints") or []),
            provider=provider,
            model=model,
            transport=str(transport or "").strip() or None,
            fallback_used=False,
            prompt_version=prompt_version,
            duration_ms=duration_ms,
        )

    def _heuristic_recommend(
        self,
        *,
        request: CapabilityAdvisoryRequest,
        target_model_summary: dict[str, Any],
        duration_ms: int,
    ) -> CapabilityAdvisoryResponse:
        focus_items = []
        for item in list(request.context.get("focus_routes") or [])[:4]:
            route = str((item or {}).get("route_group") or "").strip()
            if not route:
                continue
            focus_items.append(
                {
                    "route_group": route,
                    "priority": int((item or {}).get("advisory_priority") or (item or {}).get("risk_score") or 0),
                    "reason": str((item or {}).get("reasoning") or ""),
                }
            )
        evidence_gap_priorities = _string_list(request.context.get("evidence_gap_summary"))
        parameter_hypotheses = _heuristic_parameter_hypotheses(request.context)
        target_profile_hints = [
            {
                "key": str(item.get("key") or ""),
                "confidence": float(item.get("confidence") or 0.0),
                "reason": ", ".join(_string_list(item.get("evidence"))[:2]),
            }
            for item in list(target_model_summary.get("target_profile_hypotheses") or [])[:3]
            if str(item.get("key") or "").strip()
        ]
        workflow_segments = _heuristic_workflow_segments(request.context)
        return CapabilityAdvisoryResponse(
            pack_key=request.pack_key,
            advisory_mode=request.advisory_mode,
            focus_items=focus_items,
            evidence_gap_priorities=evidence_gap_priorities,
            parameter_hypotheses=parameter_hypotheses,
            workflow_segments=workflow_segments,
            target_profile_hints=target_profile_hints,
            provider="heuristic",
            model="rule-engine-v1",
            transport="deterministic_rules",
            fallback_used=True,
            prompt_version=str(((request.context.get("prompt_contract") or {}).get("prompt_version") or "")),
            duration_ms=duration_ms,
        )


def _extract_capability_summary(payload: dict[str, Any], *, pack_key: str) -> dict[str, Any]:
    if pack_key == "p3a_browser_xss":
        return _as_dict(payload.get("browser_xss_capability"))
    if pack_key == "p3a_multi_role_stateful_auth":
        return _as_dict(payload.get("multi_role_stateful_auth_capability"))
    if pack_key == "p3a_access_control_workflow_abuse":
        return _as_dict(payload.get("access_control_workflow_abuse_capability"))
    if pack_key == "p3a_injection":
        return _as_dict(payload.get("injection_capability"))
    if pack_key == "p3a_parser_file_abuse":
        return _as_dict(payload.get("parser_file_abuse_capability"))
    if pack_key == "p3a_disclosure_misconfig_crypto":
        return _as_dict(payload.get("disclosure_misconfig_crypto_capability"))
    capabilities = payload.get("capabilities")
    if isinstance(capabilities, dict):
        item = capabilities.get(pack_key)
        if isinstance(item, dict):
            return _as_dict(item.get("capability_summary"))
    return {}


def _extract_advisory_context(capability: dict[str, Any]) -> dict[str, Any]:
    advisory_context = capability.get("advisory_context")
    if isinstance(advisory_context, dict):
        return advisory_context
    advisory_bundle = capability.get("ai_advisory_bundle")
    if isinstance(advisory_bundle, dict):
        return advisory_bundle
    return {}


def _heuristic_parameter_hypotheses(context: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for route in list(context.get("focus_routes") or []):
        if not isinstance(route, dict):
            continue
        values.extend(_string_list(route.get("parameter_hypotheses")))
    return _string_list(values)[:8]


def _heuristic_workflow_segments(context: dict[str, Any]) -> list[dict[str, Any]]:
    routes = list(context.get("focus_routes") or [])
    if not routes:
        return []
    return [
        {
            "label": str((route or {}).get("route_group") or ""),
            "reason": str((route or {}).get("reasoning") or ""),
        }
        for route in routes[:4]
        if isinstance(route, dict) and str(route.get("route_group") or "").strip()
    ]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = str(item).strip()
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        items.append(text)
    return items


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
