"""AI Strategy Advisor — LLM-driven attack planning between phases.

Called by PipelineExecutor after each phase completes. Reviews current
findings and attack graph to recommend:
  1. Which tools to run next
  2. Which attack vectors to prioritize
  3. Which endpoints/parameters deserve deeper testing
  4. Whether to skip remaining phases (target already compromised)

Uses the same provider chain as ai_reasoning_service (Anthropic → OpenAI
→ fallback) but with a system prompt focused on offensive strategy.

CRITICAL: AI never executes anything. It only advises.
The operator (or autonomous mode) decides whether to follow advice.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Literal

from pentra_common.ai.bounded_agent import (
    BoundedAgentClient,
    BoundedAgentRequest,
    BoundedAgentResponse,
)
from pentra_common.ai.prompt_contracts import (
    build_json_user_prompt,
    strategy_prompt_contract,
)
from pentra_common.ai.provider_router import (
    ProviderRoutingOverride,
    ResolvedAIProvider,
    normalize_provider,
    resolve_provider_chain,
)
from pentra_common.config.settings import Settings, get_settings

logger = logging.getLogger(__name__)

StrategyProvider = Literal["anthropic", "openai", "groq", "ollama", "gemini"]

# ── Configuration ────────────────────────────────────────────────────

STRATEGY_SYSTEM_PROMPT = """You are Pentra AI Attack Strategist — a specialized AI advisor
embedded in an offensive security platform. You are reviewing LIVE scan
results after a completed attack phase.

Your job is to recommend the next tools and attack vectors based on
what has been discovered so far.

## Context
- You are advising a red team operator during a penetration test.
- The scan is executing in phases: recon → enum → vuln → exploit → report.
- Each phase runs multiple tools in parallel within Docker containers.
- You can recommend tools from the tool catalog to run in the next phase.

## Instructions
Based on the findings provided:
1. What tools should run next? Pick from the tool catalog.
2. What specific URLs, endpoints, or parameters deserve deeper testing?
3. Should we adjust scan intensity (rate limits, depth, breadth)?
4. Are there chained attack paths worth pursuing (e.g., SSRF → internal → RCE)?
5. Should we skip remaining phases (already fully compromised)?

## Available Tools
- subfinder, amass: subdomain discovery
- nmap_discovery, nmap_svc: host/port/service scanning
- httpx_probe: HTTP probing
- ffuf: directory/file fuzzing
- web_interact: spider/crawl
- nuclei: template-based vuln scanning
- zap: DAST web scanner
- sqlmap: SQL injection testing
- nikto: web server misconfig
- dalfox: XSS scanner
- graphql_cop: GraphQL testing
- jwt_tool: JWT analysis
- cors_scanner, cors_check: CORS testing
- header_audit, header_audit_tool: security header check
- semgrep: SAST (if source available)
- trufflehog: secret detection
- metasploit: exploit verification
- custom_poc: custom exploit scripts

Return structured JSON:
{
  "recommended_tools": [
    {"tool_id": "sqlmap", "target_url": "...", "reason": "...", "priority": "high"}
  ],
  "attack_vectors": ["sqli", "ssrf", "idor"],
  "endpoint_focus": ["/api/users/{id}", "/admin/upload"],
  "phase_decision": "proceed" | "skip_to_report" | "deep_dive",
  "strategy_notes": "Brief explanation of why these recommendations...",
  "confidence": 0.85
}
"""


@dataclass
class StrategyRecommendation:
    """Output from the AI strategy advisor."""
    recommended_tools: list[dict[str, Any]] = field(default_factory=list)
    attack_vectors: list[str] = field(default_factory=list)
    endpoint_focus: list[str] = field(default_factory=list)
    phase_decision: str = "proceed"  # proceed | skip_to_report | deep_dive
    strategy_notes: str = ""
    confidence: float = 0.0
    raw_response: str = ""
    error: str | None = None
    provider: str = ""
    model: str = ""
    transport: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

class AIStrategyAdvisor:
    """LLM-driven attack strategy advisor for scan orchestration.

    Called between phases to analyze findings and recommend next steps.
    """

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

    async def recommend(
        self,
        *,
        scan_id: uuid.UUID,
        phase_completed: int,
        phase_name: str,
        findings: list[dict[str, Any]],
        scan_config: dict[str, Any],
        tool_execution_summary: list[dict[str, Any]] | None = None,
        attack_graph: dict[str, Any] | None = None,
    ) -> StrategyRecommendation:
        """Generate strategy recommendations after a phase completes.

        Uses LLM when available, falls back to rule-based heuristics.
        """
        import time
        start = time.monotonic()

        try:
            # Build the human message with context
            user_message = self._build_context_message(
                scan_id=scan_id,
                phase_completed=phase_completed,
                phase_name=phase_name,
                findings=findings,
                scan_config=scan_config,
                tool_execution_summary=tool_execution_summary or [],
                attack_graph=attack_graph or {},
            )
            failure_reasons: list[str] = []
            for provider_config in self._provider_configs():
                try:
                    bounded_response = await self._call_provider(
                        provider_config,
                        user_message=user_message,
                    )
                    duration_ms = int((time.monotonic() - start) * 1000)
                    recommendation = self._parse_response(bounded_response.output_text)
                    recommendation.raw_response = bounded_response.output_text
                    recommendation.provider = provider_config.provider
                    recommendation.model = provider_config.model
                    recommendation.transport = bounded_response.transport
                    recommendation.duration_ms = duration_ms

                    logger.info(
                        "AI strategy recommendation for scan %s after phase %d (%s): "
                        "provider=%s decision=%s tools=%d vectors=%s confidence=%.2f",
                        scan_id,
                        phase_completed,
                        phase_name,
                        provider_config.provider,
                        recommendation.phase_decision,
                        len(recommendation.recommended_tools),
                        recommendation.attack_vectors,
                        recommendation.confidence,
                    )
                    return recommendation
                except Exception as exc:  # noqa: BLE001 - deliberate provider boundary
                    failure_reasons.append(f"{provider_config.provider}: {exc}")
                    logger.warning(
                        "AI strategy provider %s failed for scan %s after phase %d (%s): %s",
                        provider_config.provider,
                        scan_id,
                        phase_completed,
                        phase_name,
                        exc,
                    )

            if failure_reasons:
                logger.warning(
                    "AI strategy advisor exhausted providers for scan %s after phase %d (%s): %s",
                    scan_id,
                    phase_completed,
                    phase_name,
                    " | ".join(failure_reasons),
                )

            duration_ms = int((time.monotonic() - start) * 1000)
            recommendation = self._heuristic_recommend(
                phase_completed=phase_completed,
                phase_name=phase_name,
                findings=findings,
                scan_config=scan_config,
            )
            recommendation.provider = "heuristic-fallback" if failure_reasons else "heuristic"
            recommendation.model = "rule-engine-v1"
            recommendation.transport = "deterministic_rules"
            recommendation.duration_ms = duration_ms
            return recommendation
        except Exception as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.warning(
                "AI strategy advisor failed for scan %s: %s — falling back to heuristics",
                scan_id, exc,
            )
            recommendation = self._heuristic_recommend(
                phase_completed=phase_completed,
                phase_name=phase_name,
                findings=findings,
                scan_config=scan_config,
            )
            recommendation.provider = "heuristic-fallback"
            recommendation.model = "rule-engine-v1"
            recommendation.transport = "deterministic_rules"
            recommendation.duration_ms = duration_ms
            return recommendation

    def _heuristic_recommend(
        self,
        *,
        phase_completed: int,
        phase_name: str,
        findings: list[dict[str, Any]],
        scan_config: dict[str, Any],
    ) -> StrategyRecommendation:
        """Rule-based strategy when no LLM is available.

        Analyzes findings by severity/type and maps to logical next tools.
        """
        tools: list[dict[str, Any]] = []
        vectors: list[str] = []
        endpoints: list[str] = []
        decision = "proceed"
        notes_parts: list[str] = []

        # Classify findings
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        finding_types: set[str] = set()
        found_urls: list[str] = []

        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            severities[sev] = severities.get(sev, 0) + 1
            ftype = str(f.get("type", f.get("template_id", f.get("tool", "")))).lower()
            finding_types.add(ftype)
            url = f.get("url", f.get("target", f.get("host", "")))
            if url:
                found_urls.append(str(url))

        has_creds = bool(scan_config.get("credentials"))
        methodology = scan_config.get("methodology", "blackbox")

        # ── Phase-based heuristic rules ──────────────────────────────

        if phase_name in ("recon", "discovery") or phase_completed <= 1:
            # After recon → run enum/probing tools
            tools.extend([
                {"tool_id": "httpx_probe", "reason": "Probe discovered hosts for HTTP services", "priority": "high"},
                {"tool_id": "nmap_svc", "reason": "Service version detection on open ports", "priority": "high"},
            ])
            if len(found_urls) > 0:
                tools.append({"tool_id": "ffuf", "reason": "Directory/file fuzzing on discovered hosts", "priority": "medium"})
            notes_parts.append(f"Recon found {len(findings)} results. Proceeding to enumerate services.")

        elif phase_name in ("enum", "enumeration", "scanning") or phase_completed == 2:
            # After enum → run vuln scanners
            tools.extend([
                {"tool_id": "nuclei", "reason": "Template-based vulnerability scanning", "priority": "high"},
            ])
            # If web services found, add web-specific tools
            web_hints = any(
                "http" in str(f.get("url", "")).lower() or
                "web" in str(f.get("type", "")).lower()
                for f in findings
            )
            if web_hints:
                tools.extend([
                    {"tool_id": "nikto", "reason": "Web server misconfiguration check", "priority": "medium"},
                    {"tool_id": "header_audit", "reason": "Security header analysis", "priority": "low"},
                ])
                if has_creds:
                    tools.append({"tool_id": "zap", "reason": "Authenticated DAST scan", "priority": "high"})
            notes_parts.append(f"Enumeration found {len(findings)} services. Running vulnerability scanners.")

        elif phase_name in ("vuln", "vulnerability") or phase_completed == 3:
            # After vuln scan → decide based on severity
            critical_high = severities.get("critical", 0) + severities.get("high", 0)

            if critical_high > 0:
                vectors.append("exploit-verification")
                notes_parts.append(f"Found {critical_high} critical/high vulns. Recommending exploit verification.")

                # Map finding types to specific exploit tools
                for ftype in finding_types:
                    if "sqli" in ftype or "sql" in ftype:
                        tools.append({"tool_id": "sqlmap", "reason": "Verify SQL injection", "priority": "critical"})
                        vectors.append("sqli")
                    elif "xss" in ftype:
                        tools.append({"tool_id": "dalfox", "reason": "Verify XSS", "priority": "high"})
                        vectors.append("xss")
                    elif "jwt" in ftype or "token" in ftype:
                        tools.append({"tool_id": "jwt_tool", "reason": "JWT analysis", "priority": "high"})
                        vectors.append("jwt-abuse")
                    elif "graphql" in ftype:
                        tools.append({"tool_id": "graphql_cop", "reason": "GraphQL testing", "priority": "high"})
                        vectors.append("graphql")
                    elif "cors" in ftype:
                        tools.append({"tool_id": "cors_scanner", "reason": "CORS misconfiguration", "priority": "medium"})
                        vectors.append("cors")
                    elif "ssrf" in ftype:
                        vectors.append("ssrf")
                    elif "rce" in ftype or "command" in ftype:
                        vectors.append("rce")

                if not tools:
                    # Generic exploit verification for unclassified vulns
                    tools.append({"tool_id": "metasploit", "reason": "Exploit verification for discovered vulns", "priority": "high"})
            else:
                notes_parts.append("No critical/high vulnerabilities found. Proceeding to report.")
                decision = "skip_to_report" if severities.get("medium", 0) == 0 else "proceed"

        elif phase_name in ("exploit", "exploitation") or phase_completed == 4:
            # After exploit → wrap up
            decision = "proceed"  # let the report phase run
            notes_parts.append("Exploitation phase complete. Generating report.")

        # SAST tools for grey/whitebox
        if methodology in ("greybox", "whitebox") and phase_completed <= 2:
            tools.extend([
                {"tool_id": "semgrep", "reason": "Static code analysis (source available)", "priority": "high"},
                {"tool_id": "trufflehog", "reason": "Secret detection in source code", "priority": "high"},
            ])

        # Collect endpoint focus from findings
        endpoints = list(set(found_urls[:10]))

        # Deduplicate tools by tool_id
        seen: set[str] = set()
        deduped_tools = []
        for t in tools:
            if t["tool_id"] not in seen:
                seen.add(t["tool_id"])
                deduped_tools.append(t)

        return StrategyRecommendation(
            recommended_tools=deduped_tools,
            attack_vectors=list(set(vectors)),
            endpoint_focus=endpoints,
            phase_decision=decision,
            strategy_notes=" | ".join(notes_parts) or "Rule-based strategy applied.",
            confidence=0.6 if deduped_tools else 0.4,
        )

    def _build_context_message(
        self,
        *,
        scan_id: uuid.UUID,
        phase_completed: int,
        phase_name: str,
        findings: list[dict[str, Any]],
        scan_config: dict[str, Any],
        tool_execution_summary: list[dict[str, Any]],
        attack_graph: dict[str, Any],
    ) -> str:
        """Build the context message for the LLM."""
        contract = strategy_prompt_contract()
        # Sanitize config — never send credentials to external LLMs
        safe_config = {
            k: v for k, v in scan_config.items()
            if k not in ("credentials", "api_key", "token")
        }
        safe_config["has_credentials"] = bool(scan_config.get("credentials"))

        # Summarize findings (cap at 50 to avoid token overflow)
        findings_summary = findings[:50]
        if len(findings) > 50:
            findings_summary.append({
                "_note": f"Truncated {len(findings) - 50} additional findings"
            })

        return build_json_user_prompt(
            contract,
            context={
                "scan_id": str(scan_id),
                "phase_completed": phase_completed,
                "phase_name": phase_name,
                "scan_config": safe_config,
                "findings_count": len(findings),
                "findings": findings_summary,
                "tool_execution_summary": tool_execution_summary[:20],
                "attack_graph_summary": {
                    "total_nodes": len(attack_graph.get("nodes", [])),
                    "total_edges": len(attack_graph.get("edges", [])),
                    "critical_paths": attack_graph.get("critical_paths", [])[:5],
                } if attack_graph else None,
            },
            preamble=(
                "Recommend the next phase strategy for this Pentra scan. "
                "Use only the supplied context and return structured JSON."
            ),
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
            task_type="strategy",
            model_tier="default",
            override=override if override.provider is not None else None,
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
        if provider_config.request_surface == "anthropic_messages":
            return await self._call_anthropic(
                user_message,
                api_key=provider_config.api_key,
                model=provider_config.model,
                base_url=provider_config.base_url,
                anthropic_version=provider_config.anthropic_version or "2023-06-01",
            )
        if provider_config.provider == "openai":
            return await self._call_openai(
                user_message,
                api_key=provider_config.api_key,
                model=provider_config.model,
                base_url=provider_config.base_url,
            )
        return await self._call_openai_compatible(
            user_message,
            api_key=provider_config.api_key,
            model=provider_config.model,
            base_url=provider_config.base_url,
            provider=provider_config.provider,
        )

    async def _call_anthropic(
        self,
        user_message: str,
        *,
        api_key: str,
        model: str,
        base_url: str,
        anthropic_version: str,
    ) -> BoundedAgentResponse:
        return await self._client.generate(
            BoundedAgentRequest(
                provider="anthropic",
                task_type="strategy",
                model=model,
                api_key=api_key,
                base_url=base_url,
                request_surface="anthropic_messages",
                system_prompt=STRATEGY_SYSTEM_PROMPT,
                user_prompt=user_message,
                prompt_contract="pentra.ai.strategy",
                context_bundle={"user_message": user_message},
                anthropic_version=anthropic_version,
                timeout_seconds=60.0,
                max_tokens=2000,
                temperature=0.0,
            )
        )

    async def _call_openai(
        self,
        user_message: str,
        *,
        api_key: str,
        model: str,
        base_url: str,
    ) -> BoundedAgentResponse:
        """Call OpenAI's chat-completions API."""
        return await self._call_openai_compatible(
            user_message,
            api_key=api_key,
            model=model,
            base_url=base_url,
            provider="openai",
        )

    async def _call_openai_compatible(
        self,
        user_message: str,
        *,
        api_key: str,
        model: str,
        base_url: str,
        provider: str,
    ) -> BoundedAgentResponse:
        """Call an OpenAI-compatible chat-completions API."""
        return await self._client.generate(
            BoundedAgentRequest(
                provider=provider,  # type: ignore[arg-type]
                task_type="strategy",
                model=model,
                api_key=api_key,
                base_url=base_url,
                request_surface="openai_chat_completions",
                system_prompt=STRATEGY_SYSTEM_PROMPT,
                user_prompt=user_message,
                prompt_contract="pentra.ai.strategy",
                context_bundle={"user_message": user_message},
                timeout_seconds=60.0,
                max_tokens=2000,
                temperature=0.0,
            )
        )

    def _parse_response(self, raw: str) -> StrategyRecommendation:
        """Parse the LLM response into a StrategyRecommendation."""
        # Try to extract JSON from the response
        json_str = raw
        if "```json" in raw:
            json_str = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            json_str = raw.split("```")[1].split("```")[0].strip()

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            logger.warning("Failed to parse AI strategy response as JSON")
            return StrategyRecommendation(
                phase_decision="proceed",
                strategy_notes=raw[:2000],
            )

        return StrategyRecommendation(
            recommended_tools=data.get("recommended_tools", []),
            attack_vectors=data.get("attack_vectors", []),
            endpoint_focus=data.get("endpoint_focus", []),
            phase_decision=data.get("phase_decision", "proceed"),
            strategy_notes=data.get("strategy_notes", ""),
            confidence=float(data.get("confidence", 0.5)),
        )
