"""Advisory AI reasoning service built on top of persisted scan data.

Phase 5 deliberately keeps AI out of scan execution and exploit decisions.
This service only reads completed scan state, generates advisory reasoning,
and stores every prompt/output for auditability.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from pentra_common.config.settings import get_settings
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
AIReasoningProvider = Literal["anthropic", "openai", "fallback"]

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
    "confidence": 0
  },
  "report": {
    "draft_summary": "string",
    "prioritization_notes": "string",
    "remediation_focus": ["string"],
    "confidence": 0
  },
  "findings": [
    {
      "finding_id": "uuid-or-null",
      "title": "string",
      "why_it_matters": "string",
      "business_impact": "string",
      "exploitability_assessment": "string",
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
        normalized_provider = _normalize_provider(provider) or "anthropic"
        default_model = _FALLBACK_MODEL
        deep_model = _FALLBACK_MODEL
        api_key = ""
        base_url = ""
        anthropic_version: str | None = None
        reasoning_effort: str | None = None

        if normalized_provider == "openai":
            default_model = settings.openai_default_model.strip() or "gpt-5-mini"
            deep_model = settings.openai_deep_model.strip() or "gpt-5.4"
            api_key = settings.openai_api_key
            base_url = settings.openai_base_url.rstrip("/")
            reasoning_effort = (
                settings.openai_deep_reasoning_effort.strip()
                if normalized_mode == _DEEP_ADVISORY_MODE
                else settings.openai_standard_reasoning_effort.strip()
            ) or None
        else:
            default_model = (
                settings.anthropic_default_model.strip()
                or settings.anthropic_model.strip()
                or "claude-sonnet-4-20250514"
            )
            deep_model = settings.anthropic_deep_model.strip() or default_model
            api_key = settings.anthropic_api_key
            base_url = settings.anthropic_base_url.rstrip("/")
            anthropic_version = settings.anthropic_version

        return cls(
            provider=normalized_provider,
            enabled=bool(settings.ai_reasoning_enabled),
            api_key=api_key,
            model=deep_model if normalized_mode == _DEEP_ADVISORY_MODE else default_model,
            advisory_mode=normalized_mode,
            prompt_version=_prompt_version_for_mode(normalized_mode),
            base_url=base_url,
            anthropic_version=anthropic_version,
            reasoning_effort=reasoning_effort,
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

        if not self._config.api_key.strip():
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

        if not self._config.api_key.strip():
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


def _normalize_advisory_mode(advisory_mode: str | None) -> AIAdvisoryMode:
    if advisory_mode == _DEEP_ADVISORY_MODE:
        return _DEEP_ADVISORY_MODE
    return _DEFAULT_ADVISORY_MODE


def _normalize_provider(provider: str | None) -> AIReasoningProvider | None:
    normalized = str(provider or "").strip().lower()
    if normalized == "openai":
        return "openai"
    if normalized == "anthropic":
        return "anthropic"
    return None


def _provider_chain_from_settings() -> list[AIReasoningProvider]:
    chain: list[AIReasoningProvider] = []
    primary = _normalize_provider(settings.ai_reasoning_primary_provider) or "anthropic"
    fallback = _normalize_provider(settings.ai_reasoning_fallback_provider)

    for candidate in (primary, fallback):
        if candidate and candidate not in chain:
            chain.append(candidate)

    return chain or ["anthropic"]


def _prompt_version_for_mode(advisory_mode: AIAdvisoryMode) -> str:
    return f"{_PROMPT_VERSION_BASE}.{advisory_mode}"


def _build_system_prompt(advisory_mode: AIAdvisoryMode) -> str:
    if advisory_mode == _DEEP_ADVISORY_MODE:
        return f"{_BASE_SYSTEM_PROMPT.rstrip()}{_DEEP_ADVISORY_APPENDIX}"
    return _BASE_SYSTEM_PROMPT


def _context_limits_for_mode(advisory_mode: AIAdvisoryMode) -> dict[str, int]:
    if advisory_mode == _DEEP_ADVISORY_MODE:
        return _DEEP_CONTEXT_LIMITS
    return _DEFAULT_CONTEXT_LIMITS


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
        client = _build_provider_client(config)
        run = await client.generate(context)
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


def _build_provider_client(
    config: AIReasoningConfig,
) -> AnthropicReasoningClient | OpenAIReasoningClient:
    if config.provider == "openai":
        return OpenAIReasoningClient(config)
    return AnthropicReasoningClient(config)


def _build_user_prompt(
    context: dict[str, Any],
    *,
    advisory_mode: AIAdvisoryMode,
    prompt_version: str,
) -> str:
    return (
        "Generate advisory reasoning for this Pentra scan context. "
        "Keep recommendations bounded, evidence-based, and safe.\n\n"
        f"Advisory mode: {advisory_mode}\n"
        f"Prompt version: {prompt_version}\n"
        f"Context JSON:\n{json.dumps(context, indent=2, sort_keys=True, default=str)}"
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
