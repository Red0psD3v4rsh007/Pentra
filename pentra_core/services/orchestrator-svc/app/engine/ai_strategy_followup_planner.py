"""Bounded AI strategy follow-up planner for dynamic DAG expansion.

Turns selected ``deep_dive`` strategy recommendations into real dynamic
``scan_nodes`` within the currently running phase. This is the first
planner-facing bridge between the AI advisor and runtime execution.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.config.settings import Settings, get_settings

from app.engine.ai_strategy_advisor import StrategyRecommendation
from app.engine.dag_builder import ToolSpec, get_tool_catalog

logger = logging.getLogger(__name__)

_DERIVED_TOOLS = frozenset({"scope_check", "ai_triage", "report_gen"})
_ACTIVE_NODE_STATUSES = ("pending", "ready", "scheduled", "running")


@dataclass(frozen=True)
class PlannedAIStrategyFollowup:
    """A concrete dynamic follow-up node derived from AI strategy."""

    tool: str
    worker_family: str
    target_url: str
    priority: str
    reason: str
    attack_vectors: list[str]
    endpoint_focus: list[str]
    config: dict[str, Any]
    planner_action_type: str = "expand_route_family"
    route_group: str = ""
    hypothesis: str = ""
    stop_condition: str = ""
    prerequisite_evidence: list[str] = field(default_factory=list)


class AIStrategyFollowupPlanner:
    """Converts AI strategy output into bounded dynamic nodes."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        settings: Settings | None = None,
    ) -> None:
        self._session = session
        self._settings = settings or get_settings()

    def plan_followups(
        self,
        *,
        recommendation: StrategyRecommendation,
        scan_type: str,
        asset_type: str,
        scan_config: dict[str, Any],
    ) -> list[PlannedAIStrategyFollowup]:
        """Plan bounded follow-up work from a strategy recommendation."""
        if not _followup_recommended(recommendation):
            return []

        catalog = {
            tool.name: tool
            for tool in get_tool_catalog(scan_type, asset_type, scan_config)
        }
        if not catalog:
            return []

        max_followups = max(int(self._settings.max_ai_strategy_followups), 0)
        if max_followups <= 0:
            return []

        planned: list[PlannedAIStrategyFollowup] = []
        seen_tools: set[str] = set()

        for item in recommendation.recommended_tools:
            if not isinstance(item, dict):
                continue
            tool_name = str(item.get("tool_id") or "").strip()
            if not tool_name or tool_name in seen_tools or tool_name in _DERIVED_TOOLS:
                continue

            tool_spec = catalog.get(tool_name)
            if tool_spec is None:
                logger.debug("AI strategy follow-up skipped unsupported tool: %s", tool_name)
                continue

            seen_tools.add(tool_name)
            planned.append(
                self._build_planned_followup(
                    tool_spec=tool_spec,
                    recommendation=recommendation,
                    item=item,
                    scan_config=scan_config,
                )
            )
            if len(planned) >= max_followups:
                break

        return planned

    def plan_followups_for_tools(
        self,
        *,
        tool_ids: list[str],
        target_urls: list[str],
        attack_vectors: list[str],
        reason: str,
        priority: str,
        planner_action_type: str,
        route_group: str,
        hypothesis: str,
        stop_condition: str,
        prerequisite_evidence: list[str],
        scan_type: str,
        asset_type: str,
        scan_config: dict[str, Any],
        recommendation: StrategyRecommendation,
    ) -> list[PlannedAIStrategyFollowup]:
        catalog = {
            tool.name: tool
            for tool in get_tool_catalog(scan_type, asset_type, scan_config)
        }
        if not catalog:
            return []

        planned: list[PlannedAIStrategyFollowup] = []
        max_followups = max(int(self._settings.max_ai_strategy_followups), 0)
        for tool_id in _dedupe_preserve_order(tool_ids):
            if tool_id in _DERIVED_TOOLS:
                continue
            tool_spec = catalog.get(tool_id)
            if tool_spec is None:
                continue
            item = {
                "tool_id": tool_id,
                "target_url": target_urls[0] if target_urls else "",
                "reason": reason,
                "priority": priority,
                "attack_vectors": attack_vectors,
                "endpoint_focus": target_urls,
            }
            planned.append(
                self._build_planned_followup(
                    tool_spec=tool_spec,
                    recommendation=recommendation,
                    item=item,
                    scan_config=scan_config,
                    planner_action_type=planner_action_type,
                    route_group=route_group,
                    hypothesis=hypothesis,
                    stop_condition=stop_condition,
                    prerequisite_evidence=prerequisite_evidence,
                )
            )
            if len(planned) >= max_followups:
                break
        return planned

    async def apply_recommendation(
        self,
        *,
        dag_id: uuid.UUID,
        tenant_id: uuid.UUID,
        scan_type: str,
        asset_type: str,
        scan_config: dict[str, Any],
        recommendation: StrategyRecommendation,
    ) -> list[uuid.UUID]:
        """Materialize planned follow-ups as dynamic scan nodes."""
        plans = self.plan_followups(
            recommendation=recommendation,
            scan_type=scan_type,
            asset_type=asset_type,
            scan_config=scan_config,
        )
        return await self.apply_plans(
            dag_id=dag_id,
            tenant_id=tenant_id,
            plans=plans,
        )

    async def apply_plans(
        self,
        *,
        dag_id: uuid.UUID,
        tenant_id: uuid.UUID,
        plans: list[PlannedAIStrategyFollowup],
    ) -> list[uuid.UUID]:
        """Materialize pre-planned follow-ups as dynamic scan nodes."""
        phase = await self._get_running_phase(dag_id)
        if phase is None:
            return []

        if not plans:
            return []

        created: list[uuid.UUID] = []
        for plan in plans:
            if await self._dynamic_node_exists(dag_id=dag_id, plan=plan):
                continue

            node_id = uuid.uuid4()
            await self._session.execute(
                text(
                    """
                    INSERT INTO scan_nodes (
                        id, dag_id, phase_id, tenant_id, tool, worker_family,
                        status, is_dynamic, config, input_refs
                    ) VALUES (
                        :id, :did, :pid, :tid, :tool, :family,
                        'pending', true, CAST(:config AS jsonb), CAST(:input_refs AS jsonb)
                    )
                    """
                ),
                {
                    "id": str(node_id),
                    "did": str(dag_id),
                    "pid": str(phase["phase_id"]),
                    "tid": str(tenant_id),
                    "tool": plan.tool,
                    "family": plan.worker_family,
                    "config": json.dumps(plan.config),
                    "input_refs": json.dumps({}),
                },
            )
            created.append(node_id)

        if created:
            await self._session.flush()
            logger.info(
                "AI strategy follow-up planner created %d dynamic nodes for dag %s",
                len(created),
                dag_id,
            )
        return created

    async def _get_running_phase(self, dag_id: uuid.UUID) -> dict[str, uuid.UUID | int] | None:
        result = await self._session.execute(
            text(
                """
                SELECT id AS phase_id, phase_number
                FROM scan_phases
                WHERE dag_id = :did
                  AND status = 'running'
                ORDER BY phase_number ASC
                LIMIT 1
                """
            ),
            {"did": str(dag_id)},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return {
            "phase_id": uuid.UUID(str(row["phase_id"])),
            "phase_number": int(row["phase_number"]),
        }

    async def _dynamic_node_exists(
        self,
        *,
        dag_id: uuid.UUID,
        plan: PlannedAIStrategyFollowup,
    ) -> bool:
        result = await self._session.execute(
            text(
                """
                SELECT status, config
                FROM scan_nodes
                WHERE dag_id = :did
                  AND tool = :tool
                  AND is_dynamic = true
                """
            ),
            {
                "did": str(dag_id),
                "tool": plan.tool,
            },
        )
        for row in result.mappings().all():
            if str(row["status"]) not in _ACTIVE_NODE_STATUSES:
                continue
            config = row["config"] if isinstance(row["config"], dict) else {}
            if _config_matches_plan(config, plan):
                return True
        return False

    def _build_planned_followup(
        self,
        *,
        tool_spec: ToolSpec,
        recommendation: StrategyRecommendation,
        item: dict[str, Any],
        scan_config: dict[str, Any],
        planner_action_type: str = "expand_route_family",
        route_group: str = "",
        hypothesis: str = "",
        stop_condition: str = "",
        prerequisite_evidence: list[str] | None = None,
    ) -> PlannedAIStrategyFollowup:
        attack_vectors = _string_list(item.get("attack_vectors"))
        if not attack_vectors:
            attack_vectors = _string_list(recommendation.attack_vectors)

        endpoint_focus = _string_list(item.get("endpoint_focus"))
        if not endpoint_focus:
            endpoint_focus = _string_list(recommendation.endpoint_focus)

        target_url = str(item.get("target_url") or "").strip()
        if not target_url and endpoint_focus:
            target_url = endpoint_focus[0]

        priority = _normalized_priority(str(item.get("priority") or "medium"))
        reason = str(item.get("reason") or recommendation.strategy_notes or "").strip()

        config = _build_followup_config(
            tool_spec=tool_spec,
            scan_config=scan_config,
            target_url=target_url,
            attack_vectors=attack_vectors,
            endpoint_focus=endpoint_focus,
            recommendation=recommendation,
            priority=priority,
            reason=reason,
            planner_action_type=planner_action_type,
            route_group=route_group,
            hypothesis=hypothesis,
            stop_condition=stop_condition,
            prerequisite_evidence=prerequisite_evidence or [],
        )
        return PlannedAIStrategyFollowup(
            tool=tool_spec.name,
            worker_family=tool_spec.worker_family,
            target_url=target_url,
            priority=priority,
            reason=reason,
            attack_vectors=attack_vectors,
            endpoint_focus=endpoint_focus,
            config=config,
            planner_action_type=planner_action_type,
            route_group=route_group,
            hypothesis=hypothesis,
            stop_condition=stop_condition,
            prerequisite_evidence=list(prerequisite_evidence or []),
        )


def _build_followup_config(
    *,
    tool_spec: ToolSpec,
    scan_config: dict[str, Any],
    target_url: str,
    attack_vectors: list[str],
    endpoint_focus: list[str],
    recommendation: StrategyRecommendation,
    priority: str,
    reason: str,
    planner_action_type: str,
    route_group: str,
    hypothesis: str,
    stop_condition: str,
    prerequisite_evidence: list[str],
) -> dict[str, Any]:
    config: dict[str, Any] = {
        "max_retries": tool_spec.max_retries,
        "timeout_seconds": tool_spec.timeout_seconds,
        "scope": dict(scan_config.get("scope") or {}),
        "credentials": dict(scan_config.get("credentials") or {}),
        "rate_limits": dict(scan_config.get("rate_limits") or {}),
        "methodology": str(scan_config.get("methodology") or "blackbox"),
        "mode": str(scan_config.get("mode") or "autonomous"),
        "ai_strategy_generated": True,
        "ai_strategy_priority": priority,
        "ai_strategy_reason": reason,
        "ai_strategy_confidence": float(recommendation.confidence or 0.0),
        "ai_strategy_target_url": target_url,
        "ai_strategy_endpoint_focus": endpoint_focus,
        "ai_strategy_attack_vectors": attack_vectors,
        "planner_action_type": planner_action_type,
        "planner_route_group": route_group,
        "planner_hypothesis": hypothesis,
        "planner_stop_condition": stop_condition,
        "planner_prerequisite_evidence": prerequisite_evidence,
        "artifact_type_override": tool_spec.output_artifact_type,
    }

    if target_url:
        config["target_url"] = target_url
        base_url = _base_url(target_url)
        if base_url:
            config["targeting"] = {
                "base_url": base_url,
                "host": _host(target_url),
            }

    if tool_spec.name == "sqlmap" and target_url:
        config["selected_checks"] = {"sqlmap": {"path": target_url}}

    if tool_spec.name == "nuclei" and attack_vectors:
        config["command_context"] = {
            "nuclei_tags": ",".join(_dedupe_preserve_order(attack_vectors)[:6]),
        }

    if tool_spec.name == "web_interact" and endpoint_focus:
        config["sequence_urls"] = endpoint_focus[:5]

    return config


def _config_matches_plan(config: dict[str, Any], plan: PlannedAIStrategyFollowup) -> bool:
    existing_target = str(config.get("ai_strategy_target_url") or config.get("target_url") or "").strip()
    if existing_target and existing_target == plan.target_url:
        return True

    existing_focus = _string_list(config.get("ai_strategy_endpoint_focus"))
    if existing_focus and existing_focus == plan.endpoint_focus:
        return True

    existing_vectors = _string_list(config.get("ai_strategy_attack_vectors"))
    if existing_vectors and existing_vectors == plan.attack_vectors:
        return True

    return False


def _normalized_priority(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"critical", "high", "medium", "low"}:
        return normalized
    return "medium"


def _followup_recommended(recommendation: StrategyRecommendation) -> bool:
    decision = str(recommendation.phase_decision or "").strip().lower()
    if decision == "skip_to_report":
        return False
    return bool(recommendation.recommended_tools)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        text = str(item).strip()
        if text:
            items.append(text)
    return _dedupe_preserve_order(items)


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        key = item.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _base_url(target_url: str) -> str:
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _host(target_url: str) -> str:
    parsed = urlparse(target_url)
    return parsed.hostname or ""
