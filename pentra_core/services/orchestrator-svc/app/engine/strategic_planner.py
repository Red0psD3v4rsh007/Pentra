"""Phase 9 strategic planner.

Builds a planner-visible intent from AI strategy output and runtime context.
This keeps planning decisions explicit and auditable instead of hiding them
inside executor branching.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.engine.ai_strategy_advisor import StrategyRecommendation
from app.engine.planner_target_model_loader import PlannerTargetModelSummary, PlannerRouteGroupSummary

_NOISY_SCANNERS = frozenset({"nuclei", "nikto", "zap"})
_AUTH_FOCUSED_TOOLS = ("web_interact", "custom_poc", "ffuf")
_WORKFLOW_TOOLS = ("web_interact", "custom_poc", "ffuf")
_VERIFICATION_TOOLS = ("sqlmap", "web_interact", "custom_poc")
_PARAMETER_TOOLS = ("sqlmap", "ffuf")
_BROWSER_XSS_TOOLS = ("web_interact", "custom_poc")
_PARSER_TOOLS = ("web_interact", "custom_poc")
_DISCLOSURE_TOOLS = ("web_interact", "httpx_probe", "custom_poc", "ffuf")


@dataclass(frozen=True)
class StrategicPlannerContext:
    """Planner-visible runtime context at a phase boundary."""

    scan_id: str
    dag_id: str
    scan_type: str
    asset_type: str
    phase_completed: int
    current_progress: int
    template_node_count: int
    template_tool_ids: list[str]
    active_phase_tool_ids: list[str]
    recommendation: StrategyRecommendation
    target_model: PlannerTargetModelSummary | None


@dataclass(frozen=True)
class PlannerAction:
    """An explicit planner action derived from target-model and truth pressure."""

    action_type: str
    route_group: str
    objective: str
    hypothesis: str
    rationale: str
    target_urls: list[str]
    preferred_tool_ids: list[str]
    suppressed_tool_ids: list[str]
    prerequisite_evidence: list[str]
    expected_value: str
    stop_condition: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "route_group": self.route_group,
            "objective": self.objective,
            "hypothesis": self.hypothesis,
            "rationale": self.rationale,
            "target_urls": list(self.target_urls),
            "preferred_tool_ids": list(self.preferred_tool_ids),
            "suppressed_tool_ids": list(self.suppressed_tool_ids),
            "prerequisite_evidence": list(self.prerequisite_evidence),
            "expected_value": self.expected_value,
            "stop_condition": self.stop_condition,
        }


@dataclass(frozen=True)
class StrategicPlan:
    """High-level intent that guides tactical mutation."""

    decision: str
    objective: str
    rationale: str
    expected_path_change: str
    recommended_tool_ids: list[str]
    suppressed_tool_ids: list[str]
    endpoint_focus: list[str]
    attack_vectors: list[str]
    actions: list[PlannerAction]
    measurable_effect_expected: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "objective": self.objective,
            "rationale": self.rationale,
            "expected_path_change": self.expected_path_change,
            "recommended_tool_ids": list(self.recommended_tool_ids),
            "suppressed_tool_ids": list(self.suppressed_tool_ids),
            "endpoint_focus": list(self.endpoint_focus),
            "attack_vectors": list(self.attack_vectors),
            "actions": [action.to_dict() for action in self.actions],
            "measurable_effect_expected": self.measurable_effect_expected,
        }


class StrategicPlanner:
    """Derive a high-level runtime plan from AI strategy output."""

    def build_plan(self, context: StrategicPlannerContext) -> StrategicPlan:
        recommendation = context.recommendation
        recommended_tool_ids = _recommended_tool_ids(recommendation)
        endpoint_focus = _string_list(recommendation.endpoint_focus)
        attack_vectors = _string_list(recommendation.attack_vectors)
        template_tool_ids = _dedupe_preserve_order(context.template_tool_ids)
        active_phase_tool_ids = _dedupe_preserve_order(context.active_phase_tool_ids)
        top_focus = context.target_model.top_focus if context.target_model else None
        top_target_profile = _top_target_profile_key(context.target_model)
        auth_pack_pressure = _capability_pressure_score(
            context.target_model,
            pack_key="p3a_multi_role_stateful_auth",
        )
        access_workflow_pack_pressure = _capability_pressure_score(
            context.target_model,
            pack_key="p3a_access_control_workflow_abuse",
        )
        injection_pack_pressure = _capability_pressure_score(
            context.target_model,
            pack_key="p3a_injection",
        )
        parser_pack_pressure = _capability_pressure_score(
            context.target_model,
            pack_key="p3a_parser_file_abuse",
        )
        disclosure_pack_pressure = _capability_pressure_score(
            context.target_model,
            pack_key="p3a_disclosure_misconfig_crypto",
        )
        graph_preferred_action_keys = _graph_preferred_action_keys(
            context.target_model,
            route_group=top_focus.route_group if top_focus else "",
        )
        graph_rationale = _graph_rationale(
            context.target_model,
            route_group=top_focus.route_group if top_focus else "",
        )

        if recommendation.phase_decision == "skip_to_report":
            return StrategicPlan(
                decision="compress_to_report",
                objective="Respect the strategist decision to avoid further depth.",
                rationale=recommendation.strategy_notes or "AI recommended report compression.",
                expected_path_change="skip_remaining_depth",
                recommended_tool_ids=recommended_tool_ids,
                suppressed_tool_ids=[],
                endpoint_focus=endpoint_focus,
                attack_vectors=attack_vectors,
                actions=[],
                measurable_effect_expected=False,
            )

        if top_focus is not None and top_focus.focus_score > 0:
            actions = _build_target_model_actions(
                top_focus=top_focus,
                top_target_profile=top_target_profile,
                auth_pack_pressure=auth_pack_pressure,
                access_workflow_pack_pressure=access_workflow_pack_pressure,
                injection_pack_pressure=injection_pack_pressure,
                parser_pack_pressure=parser_pack_pressure,
                disclosure_pack_pressure=disclosure_pack_pressure,
                graph_preferred_action_keys=graph_preferred_action_keys,
                graph_rationale=graph_rationale,
                preferred_candidate_tool_ids=template_tool_ids,
                suppression_candidate_tool_ids=active_phase_tool_ids or template_tool_ids,
                recommended_tool_ids=recommended_tool_ids,
                recommendation=recommendation,
            )
            if actions:
                preferred_tool_ids = _dedupe_preserve_order(
                    [tool for action in actions for tool in action.preferred_tool_ids]
                )
                suppressed_tool_ids = _dedupe_preserve_order(
                    [tool for action in actions for tool in action.suppressed_tool_ids]
                )
                action_endpoint_focus = _dedupe_preserve_order(
                    [url for action in actions for url in action.target_urls]
                ) or endpoint_focus
                objective = "; ".join(action.objective for action in actions[:2])
                rationale = " | ".join(action.rationale for action in actions[:2])
                expected_path_change = _expected_path_change(
                    preferred_tool_ids=preferred_tool_ids,
                    suppressed_tool_ids=suppressed_tool_ids,
                )
                decision = (
                    "rebalance_phase"
                    if preferred_tool_ids and suppressed_tool_ids
                    else "expand_current_phase"
                    if preferred_tool_ids
                    else "suppress_low_value_tools"
                )
                return StrategicPlan(
                    decision=decision,
                    objective=objective,
                    rationale=rationale,
                    expected_path_change=expected_path_change,
                    recommended_tool_ids=preferred_tool_ids,
                    suppressed_tool_ids=suppressed_tool_ids,
                    endpoint_focus=action_endpoint_focus,
                    attack_vectors=attack_vectors,
                    actions=actions,
                    measurable_effect_expected=bool(preferred_tool_ids or suppressed_tool_ids),
                )

        if recommended_tool_ids:
            objective_bits: list[str] = []
            if attack_vectors:
                objective_bits.append(f"pressure {'/'.join(attack_vectors[:3])}")
            if endpoint_focus:
                objective_bits.append(f"focus {endpoint_focus[0]}")
            if not objective_bits:
                objective_bits.append("deepen the current phase with targeted follow-up work")

            return StrategicPlan(
                decision="expand_current_phase",
                objective=", ".join(objective_bits),
                rationale=recommendation.strategy_notes or "AI recommended targeted follow-up tools.",
                expected_path_change="add_dynamic_followups",
                recommended_tool_ids=recommended_tool_ids,
                suppressed_tool_ids=[],
                endpoint_focus=endpoint_focus,
                attack_vectors=attack_vectors,
                actions=[
                    PlannerAction(
                        action_type="expand_route_family",
                        route_group=top_focus.route_group if top_focus else "",
                        objective=", ".join(objective_bits),
                        hypothesis=recommendation.strategy_notes or "Expand current route family pressure.",
                        rationale=recommendation.strategy_notes or "AI recommended targeted follow-up tools.",
                        target_urls=endpoint_focus,
                        preferred_tool_ids=recommended_tool_ids,
                        suppressed_tool_ids=[],
                        prerequisite_evidence=["phase_boundary_summary"],
                        expected_value="increase route coverage and close evidence gaps",
                        stop_condition="stop after bounded follow-up insertion or if no supported tools remain",
                    )
                ],
                measurable_effect_expected=True,
            )

        return StrategicPlan(
            decision="maintain_course",
            objective="Continue the static scan path.",
            rationale=recommendation.strategy_notes or "No concrete tool follow-ups were recommended.",
            expected_path_change="none",
            recommended_tool_ids=[],
            suppressed_tool_ids=[],
            endpoint_focus=endpoint_focus,
            attack_vectors=attack_vectors,
            actions=[],
            measurable_effect_expected=False,
        )


def _recommended_tool_ids(recommendation: StrategyRecommendation) -> list[str]:
    seen: set[str] = set()
    tool_ids: list[str] = []
    for item in recommendation.recommended_tools:
        if not isinstance(item, dict):
            continue
        tool_id = str(item.get("tool_id") or "").strip()
        key = tool_id.lower()
        if not tool_id or key in seen:
            continue
        seen.add(key)
        tool_ids.append(tool_id)
    return tool_ids


def _build_target_model_actions(
    *,
    top_focus: PlannerRouteGroupSummary,
    top_target_profile: str,
    auth_pack_pressure: int,
    access_workflow_pack_pressure: int,
    injection_pack_pressure: int,
    parser_pack_pressure: int,
    disclosure_pack_pressure: int,
    graph_preferred_action_keys: list[str],
    graph_rationale: list[str],
    preferred_candidate_tool_ids: list[str],
    suppression_candidate_tool_ids: list[str],
    recommended_tool_ids: list[str],
    recommendation: StrategyRecommendation,
) -> list[PlannerAction]:
    actions: list[PlannerAction] = []
    combined_tool_ids = _dedupe_preserve_order(recommended_tool_ids + preferred_candidate_tool_ids)
    suppressed_tool_ids = _suppressed_tool_ids(
        top_focus=top_focus,
        candidate_tool_ids=suppression_candidate_tool_ids,
    )
    preferred_tool_ids = _preferred_tool_ids(
        top_focus=top_focus,
        top_target_profile=top_target_profile,
        auth_pack_pressure=auth_pack_pressure,
        access_workflow_pack_pressure=access_workflow_pack_pressure,
        injection_pack_pressure=injection_pack_pressure,
        parser_pack_pressure=parser_pack_pressure,
        disclosure_pack_pressure=disclosure_pack_pressure,
        candidate_tool_ids=combined_tool_ids,
    )

    if preferred_tool_ids:
        action_type = _preferred_action_type(
            top_focus,
            top_target_profile=top_target_profile,
            auth_pack_pressure=auth_pack_pressure,
            access_workflow_pack_pressure=access_workflow_pack_pressure,
            injection_pack_pressure=injection_pack_pressure,
            parser_pack_pressure=parser_pack_pressure,
            disclosure_pack_pressure=disclosure_pack_pressure,
            graph_preferred_action_keys=graph_preferred_action_keys,
        )
        rationale = recommendation.strategy_notes or f"Target-model pressure is highest on {top_focus.route_group}."
        if graph_rationale:
            rationale = f"{rationale} Graph alignment: {'; '.join(graph_rationale[:2])}."
        actions.append(
            PlannerAction(
                action_type=action_type,
                route_group=top_focus.route_group,
                objective=_planner_objective(
                    top_focus,
                    action_type=action_type,
                    top_target_profile=top_target_profile,
                ),
                hypothesis=_planner_hypothesis(
                    top_focus,
                    action_type=action_type,
                    top_target_profile=top_target_profile,
                ),
                rationale=rationale,
                target_urls=top_focus.endpoint_urls,
                preferred_tool_ids=preferred_tool_ids,
                suppressed_tool_ids=[],
                prerequisite_evidence=list(top_focus.evidence_gaps) or ["target_model_focus"],
                expected_value=_expected_value(top_focus, action_type=action_type),
                stop_condition=_stop_condition(top_focus, action_type),
            )
        )

    if suppressed_tool_ids:
        actions.append(
            PlannerAction(
                action_type="pause_noisy_tool_family",
                route_group=top_focus.route_group,
                objective=f"Reduce low-value tool noise around {top_focus.route_group}.",
                hypothesis="Generic scanner pressure is too noisy relative to current evidence quality.",
                rationale="Suppress broad scanner work until the planner has clearer parameter/auth/verification pressure.",
                target_urls=top_focus.endpoint_urls,
                preferred_tool_ids=[],
                suppressed_tool_ids=suppressed_tool_ids,
                prerequisite_evidence=["low_signal_generic_scanning"],
                expected_value="reduce false-positive-heavy work and preserve operator attention",
                stop_condition="stop suppression when stronger target-model pressure or verified proof appears",
            )
        )

    return actions


def _preferred_action_type(
    top_focus: PlannerRouteGroupSummary,
    *,
    top_target_profile: str,
    auth_pack_pressure: int,
    access_workflow_pack_pressure: int,
    injection_pack_pressure: int,
    parser_pack_pressure: int,
    disclosure_pack_pressure: int,
    graph_preferred_action_keys: list[str],
) -> str:
    vulnerability_types = set(top_focus.vulnerability_types)
    graph_action = _graph_action_choice(
        top_focus,
        top_target_profile=top_target_profile,
        auth_pack_pressure=auth_pack_pressure,
        access_workflow_pack_pressure=access_workflow_pack_pressure,
        injection_pack_pressure=injection_pack_pressure,
        parser_pack_pressure=parser_pack_pressure,
        disclosure_pack_pressure=disclosure_pack_pressure,
        graph_preferred_action_keys=graph_preferred_action_keys,
    )
    if graph_action:
        return graph_action
    if _has_browser_xss_pressure(top_focus):
        if top_focus.truth_counts.get("suspected", 0) or "verification" in top_focus.evidence_gaps:
            return "stage_route_specific_xss_payloads"
        return "map_client_side_sinks"
    if _has_injection_pressure(top_focus) or injection_pack_pressure > 0:
        return "verify_suspected_injection"
    if _has_parser_pressure(top_focus) or parser_pack_pressure > 0:
        return "probe_parser_boundaries"
    if _has_stack_trace_pressure(top_focus):
        return "inspect_error_and_log_disclosure"
    if _has_component_truth_pressure(top_focus):
        return "fingerprint_components_and_hidden_assets"
    if _has_disclosure_pressure(top_focus) or disclosure_pack_pressure > 0:
        return "inspect_config_and_secret_exposure"
    if _has_privileged_auth_pressure(top_focus) or _has_access_control_privileged_surface(top_focus):
        return "enumerate_privileged_api_surface"
    if _has_workflow_abuse_pressure(top_focus) or (
        access_workflow_pack_pressure > 0
        and top_target_profile == "workflow_heavy_commerce"
        and top_focus.workflow_edge_count > 0
    ):
        return "mutate_business_workflows"
    if _has_access_control_pressure(top_focus) or access_workflow_pack_pressure > 0:
        return "compare_role_access"
    if _has_auth_pressure(top_focus) or auth_pack_pressure > 0:
        if "auth_transition_pressure" in {item.lower() for item in top_focus.interaction_kinds}:
            return "pressure_auth_tokens_and_login_flows"
        if top_target_profile in {"auth_heavy_admin_portal", "workflow_heavy_commerce"} or top_focus.requires_auth:
            return "compare_role_access"
    if top_focus.requires_auth or {"auth_bypass", "idor", "workflow_bypass"} & vulnerability_types:
        return "deepen_auth_context_probe"
    if "verification" in top_focus.evidence_gaps or "sql_injection" in vulnerability_types:
        return "verify_suspected_issue"
    return "expand_route_family"


def _graph_action_choice(
    top_focus: PlannerRouteGroupSummary,
    *,
    top_target_profile: str,
    auth_pack_pressure: int,
    access_workflow_pack_pressure: int,
    injection_pack_pressure: int,
    parser_pack_pressure: int,
    disclosure_pack_pressure: int,
    graph_preferred_action_keys: list[str],
) -> str:
    for action_type in _dedupe_preserve_order(graph_preferred_action_keys):
        if action_type in {"map_client_side_sinks", "stage_route_specific_xss_payloads", "replay_stored_xss_workflow"}:
            if _has_browser_xss_pressure(top_focus):
                return action_type
            continue
        if action_type == "verify_suspected_injection":
            if _has_injection_pressure(top_focus) or injection_pack_pressure > 0:
                return action_type
            continue
        if action_type == "probe_parser_boundaries":
            if _has_parser_pressure(top_focus) or parser_pack_pressure > 0:
                return action_type
            continue
        if action_type == "inspect_error_and_log_disclosure":
            if _has_stack_trace_pressure(top_focus):
                return action_type
            continue
        if action_type == "fingerprint_components_and_hidden_assets":
            if _has_component_truth_pressure(top_focus):
                return action_type
            continue
        if action_type == "inspect_config_and_secret_exposure":
            if _has_disclosure_pressure(top_focus) or disclosure_pack_pressure > 0:
                return action_type
            continue
        if action_type == "enumerate_privileged_api_surface":
            if _has_privileged_auth_pressure(top_focus) or _has_access_control_privileged_surface(top_focus):
                return action_type
            continue
        if action_type == "mutate_business_workflows":
            if _has_workflow_abuse_pressure(top_focus) or (
                access_workflow_pack_pressure > 0
                and top_target_profile == "workflow_heavy_commerce"
                and top_focus.workflow_edge_count > 0
            ):
                return action_type
            continue
        if action_type == "compare_role_access":
            if _has_access_control_pressure(top_focus) or access_workflow_pack_pressure > 0:
                return action_type
            if _has_auth_pressure(top_focus) or auth_pack_pressure > 0:
                return action_type
            continue
        if action_type == "pressure_auth_tokens_and_login_flows":
            if _has_auth_pressure(top_focus) or auth_pack_pressure > 0:
                return action_type
            continue
        if action_type == "validate_redirect_targets":
            if "unvalidated_redirect" in set(top_focus.vulnerability_types):
                return action_type
            continue
    return ""


def _preferred_tool_ids(
    *,
    top_focus: PlannerRouteGroupSummary,
    top_target_profile: str,
    auth_pack_pressure: int,
    access_workflow_pack_pressure: int,
    injection_pack_pressure: int,
    parser_pack_pressure: int,
    disclosure_pack_pressure: int,
    candidate_tool_ids: list[str],
) -> list[str]:
    candidate_set = {item.lower(): item for item in candidate_tool_ids}
    ordered: list[str] = []
    vulnerability_types = set(top_focus.vulnerability_types)

    if _has_browser_xss_pressure(top_focus):
        ordered.extend(item for item in _BROWSER_XSS_TOOLS if item in candidate_set)

    if (
        _has_workflow_abuse_pressure(top_focus)
        or access_workflow_pack_pressure > 0
        or top_target_profile == "workflow_heavy_commerce"
    ):
        ordered.extend(item for item in _WORKFLOW_TOOLS if item in candidate_set)

    if (
        _has_injection_pressure(top_focus)
        or injection_pack_pressure > 0
        or "sql_injection" in vulnerability_types
        or "nosql_injection" in vulnerability_types
        or "graphql_injection" in vulnerability_types
    ):
        ordered.extend(item for item in _VERIFICATION_TOOLS if item in candidate_set)
        ordered.extend(item for item in _PARAMETER_TOOLS if item in candidate_set)

    if (
        _has_parser_pressure(top_focus)
        or parser_pack_pressure > 0
        or "xxe" in vulnerability_types
        or "insecure_deserialization" in vulnerability_types
    ):
        ordered.extend(item for item in _PARSER_TOOLS if item in candidate_set)

    if (
        _has_disclosure_pressure(top_focus)
        or disclosure_pack_pressure > 0
        or {
            "sensitive_data_exposure",
            "stack_trace_exposure",
            "openapi_exposure",
            "credential_exposure",
            "debug_exposure",
            "cors_misconfiguration",
        } & vulnerability_types
    ):
        ordered.extend(item for item in _DISCLOSURE_TOOLS if item in candidate_set)

    if (
        _has_access_control_pressure(top_focus)
        or _has_auth_pressure(top_focus)
        or _has_privileged_auth_pressure(top_focus)
        or auth_pack_pressure > 0
        or access_workflow_pack_pressure > 0
        or top_target_profile in {"auth_heavy_admin_portal", "workflow_heavy_commerce"}
        or top_focus.requires_auth
        or {"auth_bypass", "idor", "workflow_bypass"} & vulnerability_types
    ):
        ordered.extend(item for item in _AUTH_FOCUSED_TOOLS if item in candidate_set)

    if top_focus.parameter_names or "sql_injection" in vulnerability_types:
        ordered.extend(item for item in _VERIFICATION_TOOLS if item in candidate_set)
        ordered.extend(item for item in _PARAMETER_TOOLS if item in candidate_set)

    if not ordered and candidate_tool_ids:
        ordered.extend(item for item in candidate_tool_ids if item not in _NOISY_SCANNERS)
    if not ordered:
        ordered.extend(item for item in candidate_tool_ids if item in _NOISY_SCANNERS)

    return _dedupe_preserve_order(ordered)


def _suppressed_tool_ids(
    *,
    top_focus: PlannerRouteGroupSummary,
    candidate_tool_ids: list[str],
) -> list[str]:
    if top_focus.parameter_names or top_focus.truth_counts.get("suspected", 0) or top_focus.truth_counts.get("reproduced", 0):
        return [tool for tool in candidate_tool_ids if tool in _NOISY_SCANNERS]
    if top_focus.focus_score <= 2:
        return [tool for tool in candidate_tool_ids if tool in _NOISY_SCANNERS]
    return []


def _planner_objective(
    top_focus: PlannerRouteGroupSummary,
    *,
    action_type: str,
    top_target_profile: str,
) -> str:
    if _has_browser_xss_pressure(top_focus):
        return f"Map dangerous client-side sink flow and verify benign canary propagation on {top_focus.route_group}."
    if action_type == "verify_suspected_injection":
        return f"Preserve request shape and verify bounded injection differentials on {top_focus.route_group}."
    if action_type == "probe_parser_boundaries":
        return f"Preserve parser input shape and verify bounded XML or object-handling differentials on {top_focus.route_group}."
    if action_type == "inspect_error_and_log_disclosure":
        return f"Replay candidate error conditions on {top_focus.route_group} and capture exact internal disclosure markers."
    if action_type == "inspect_config_and_secret_exposure":
        return f"Capture replayable disclosure, secret, or config truth on {top_focus.route_group} without generic route-name promotion."
    if action_type == "fingerprint_components_and_hidden_assets":
        return f"Confirm component truth and hidden-asset evidence around {top_focus.route_group} before any component claim is promoted."
    if action_type == "enumerate_privileged_api_surface":
        return f"Compare privileged route and API exposure on {top_focus.route_group} across identities."
    if action_type == "compare_role_access":
        return f"Build a multi-role outcome matrix for {top_focus.route_group} and preserve differential evidence."
    if action_type == "mutate_business_workflows":
        return f"Replay and mutate the workflow around {top_focus.route_group} to expose order, step, or state abuse."
    if action_type == "pressure_auth_tokens_and_login_flows":
        return f"Stress login, token, and auth-transition behavior on {top_focus.route_group} with replayable context."
    if top_focus.requires_auth:
        return f"Deepen authenticated understanding and privilege pressure on {top_focus.route_group}."
    if top_target_profile == "workflow_heavy_commerce":
        return f"Expand workflow-aware replay around {top_focus.route_group}."
    if top_focus.parameter_names:
        return f"Close verification gaps on {top_focus.route_group} with parameter-aware follow-up."
    return f"Expand the highest-pressure route family {top_focus.route_group}."


def _planner_hypothesis(
    top_focus: PlannerRouteGroupSummary,
    *,
    action_type: str,
    top_target_profile: str,
) -> str:
    if _has_browser_xss_pressure(top_focus):
        return "The route group likely contains a client-side source-to-sink flow that can be confirmed more safely with browser canary instrumentation than with generic scanning."
    if action_type == "verify_suspected_injection":
        return "The route group likely contains replayable parameter or query-shape drift that should be verified with bounded differentials instead of another generic sweep."
    if action_type == "probe_parser_boundaries":
        return "The route group likely contains a replayable parser boundary where XML or serialized inputs will produce higher-signal evidence than another generic sweep."
    if action_type == "inspect_error_and_log_disclosure":
        return "The route group likely exposes verbose error or stack-trace evidence that should be reproduced with bounded replay rather than another generic sweep."
    if action_type == "inspect_config_and_secret_exposure":
        return "The route group likely exposes replayable config, secret, or misconfiguration detail that should be captured directly instead of inferred from naming."
    if action_type == "fingerprint_components_and_hidden_assets":
        return "The route group likely contains replayable component or hidden-asset truth that should be separated from unsupported fingerprint guesses."
    if action_type == "enumerate_privileged_api_surface":
        return "The route group likely exposes privileged behavior or responses that only become clear through identity-aware replay."
    if action_type == "compare_role_access":
        return "The route group likely contains access-control drift that requires direct anonymous/user/admin comparison."
    if action_type == "mutate_business_workflows":
        return "The route group likely sits inside a stateful workflow where order, replay, or identifier mutation will expose higher-signal flaws than isolated requests."
    if action_type == "pressure_auth_tokens_and_login_flows":
        return "The route group likely hides session or auth-transition mistakes that only appear under structured replay."
    if "verification" in top_focus.evidence_gaps:
        return "The route group has enough pressure that replayable verification should produce higher-signal evidence than another generic sweep."
    if top_focus.requires_auth:
        return "The route group is likely hiding workflow or authorization defects behind authenticated transitions."
    if top_target_profile == "workflow_heavy_commerce":
        return "The route group sits inside a stateful workflow where sequence-aware replay should outperform generic probing."
    return "The route group contains concentrated attack-surface signals worth focused follow-up."


def _expected_value(top_focus: PlannerRouteGroupSummary, *, action_type: str) -> str:
    if _has_browser_xss_pressure(top_focus):
        return "turn client-side sink clues into route-specific, browser-observed proof with lower false positives"
    if action_type == "verify_suspected_injection":
        return "turn parameter and request-shape pressure into replayable injection evidence and demote heuristic-only routes faster"
    if action_type == "probe_parser_boundaries":
        return "turn upload and parser pressure into replayable XML or deserialization evidence and demote heuristic-only routes faster"
    if action_type == "inspect_error_and_log_disclosure":
        return "turn verbose error pressure into replayable disclosure evidence and demote benign failures faster"
    if action_type == "inspect_config_and_secret_exposure":
        return "turn disclosure and misconfiguration pressure into exact route and field evidence instead of generic route-name guesses"
    if action_type == "fingerprint_components_and_hidden_assets":
        return "turn component hints into asset-truth evidence and demote unsupported fingerprint guesses faster"
    if action_type in {"compare_role_access", "enumerate_privileged_api_surface"}:
        return "surface replayable role differentials and demote converged behavior faster"
    if action_type == "mutate_business_workflows":
        return "turn workflow-state pressure into bounded replay evidence instead of isolated route guesses"
    if action_type == "pressure_auth_tokens_and_login_flows":
        return "turn auth-surface pressure into session and transition evidence instead of generic auth guesses"
    if "verification" in top_focus.evidence_gaps:
        return "increase proof quality and demote weak observations faster"
    if top_focus.requires_auth:
        return "surface stateful access and workflow pressure more effectively than generic scanning"
    return "increase target understanding with bounded, route-specific work"


def _stop_condition(top_focus: PlannerRouteGroupSummary, action_type: str) -> str:
    if action_type == "pause_noisy_tool_family":
        return "resume once stronger target-model pressure exists"
    if action_type == "verify_suspected_injection":
        return "stop after bounded replay produces a stable differential or strong contradictory evidence"
    if action_type == "probe_parser_boundaries":
        return "stop after bounded parser replay produces a stable differential or strong contradictory evidence"
    if action_type == "inspect_error_and_log_disclosure":
        return "stop after bounded replay confirms verbose disclosure or produces strong contradictory evidence"
    if action_type == "inspect_config_and_secret_exposure":
        return "stop after bounded replay confirms disclosed fields or route truth, or contradictory evidence accumulates"
    if action_type == "fingerprint_components_and_hidden_assets":
        return "stop after exact asset truth is captured or the component hint is disproven"
    if action_type in {"compare_role_access", "enumerate_privileged_api_surface"}:
        return "stop after the available identities have been compared or behavior converges"
    if action_type == "mutate_business_workflows":
        return "stop after bounded workflow mutations produce proof or contradictory evidence"
    if action_type == "pressure_auth_tokens_and_login_flows":
        return "stop after login/token/reset replay produces proof or strong contradictory evidence"
    if "verification" in top_focus.evidence_gaps:
        return "stop after replayable proof or contradictory evidence is produced"
    return "stop after bounded route-specific evidence expansion completes"


def _has_browser_xss_pressure(top_focus: PlannerRouteGroupSummary) -> bool:
    vulnerability_types = {item.lower() for item in top_focus.vulnerability_types}
    interaction_kinds = {item.lower() for item in top_focus.interaction_kinds}
    return bool(
        "xss" in vulnerability_types
        or "xss_candidate" in interaction_kinds
        or "xss_route_pressure" in interaction_kinds
        or "xss_source_pressure" in interaction_kinds
    )


def _has_auth_pressure(top_focus: PlannerRouteGroupSummary) -> bool:
    interaction_kinds = {item.lower() for item in top_focus.interaction_kinds}
    vulnerability_types = {item.lower() for item in top_focus.vulnerability_types}
    return bool(
        "auth_candidate" in interaction_kinds
        or "auth_role_pressure" in interaction_kinds
        or "auth_transition_pressure" in interaction_kinds
        or {"auth_bypass", "idor", "workflow_bypass"} & vulnerability_types
    )


def _has_injection_pressure(top_focus: PlannerRouteGroupSummary) -> bool:
    interaction_kinds = {item.lower() for item in top_focus.interaction_kinds}
    vulnerability_types = {item.lower() for item in top_focus.vulnerability_types}
    return bool(
        "injection_candidate" in interaction_kinds
        or "graphql_candidate" in interaction_kinds
        or "injection_heuristic_pressure" in interaction_kinds
        or {"sql_injection", "nosql_injection", "graphql_injection"} & vulnerability_types
    )


def _has_parser_pressure(top_focus: PlannerRouteGroupSummary) -> bool:
    interaction_kinds = {item.lower() for item in top_focus.interaction_kinds}
    vulnerability_types = {item.lower() for item in top_focus.vulnerability_types}
    return bool(
        "parser_candidate" in interaction_kinds
        or "xxe_candidate" in interaction_kinds
        or "deserialization_candidate" in interaction_kinds
        or "parser_heuristic_pressure" in interaction_kinds
        or {"xxe", "insecure_deserialization"} & vulnerability_types
    )


def _has_stack_trace_pressure(top_focus: PlannerRouteGroupSummary) -> bool:
    interaction_kinds = {item.lower() for item in top_focus.interaction_kinds}
    vulnerability_types = {item.lower() for item in top_focus.vulnerability_types}
    return bool(
        "stack_trace_candidate" in interaction_kinds
        or "debug_surface" in interaction_kinds
        or {"stack_trace_exposure", "debug_exposure"} & vulnerability_types
    )


def _has_component_truth_pressure(top_focus: PlannerRouteGroupSummary) -> bool:
    interaction_kinds = {item.lower() for item in top_focus.interaction_kinds}
    vulnerability_types = {item.lower() for item in top_focus.vulnerability_types}
    return bool(
        "component_truth_candidate" in interaction_kinds
        or "component_surface" in interaction_kinds
        or "openapi_exposure" in vulnerability_types
    )


def _has_disclosure_pressure(top_focus: PlannerRouteGroupSummary) -> bool:
    interaction_kinds = {item.lower() for item in top_focus.interaction_kinds}
    vulnerability_types = {item.lower() for item in top_focus.vulnerability_types}
    return bool(
        "disclosure_candidate" in interaction_kinds
        or "misconfiguration_candidate" in interaction_kinds
        or "weak_crypto_candidate" in interaction_kinds
        or "disclosure_heuristic_pressure" in interaction_kinds
        or "secret_surface" in interaction_kinds
        or "crypto_surface" in interaction_kinds
        or "config_surface" in interaction_kinds
        or {
            "sensitive_data_exposure",
            "credential_exposure",
            "cors_misconfiguration",
        } & vulnerability_types
    )


def _has_privileged_auth_pressure(top_focus: PlannerRouteGroupSummary) -> bool:
    interaction_kinds = {item.lower() for item in top_focus.interaction_kinds}
    return "auth_privileged_surface" in interaction_kinds


def _has_access_control_pressure(top_focus: PlannerRouteGroupSummary) -> bool:
    interaction_kinds = {item.lower() for item in top_focus.interaction_kinds}
    vulnerability_types = {item.lower() for item in top_focus.vulnerability_types}
    return bool(
        "access_control_candidate" in interaction_kinds
        or "access_control_privileged_surface" in interaction_kinds
        or {"idor", "privilege_escalation", "auth_bypass"} & vulnerability_types
    )


def _has_access_control_privileged_surface(top_focus: PlannerRouteGroupSummary) -> bool:
    interaction_kinds = {item.lower() for item in top_focus.interaction_kinds}
    return "access_control_privileged_surface" in interaction_kinds


def _has_workflow_abuse_pressure(top_focus: PlannerRouteGroupSummary) -> bool:
    interaction_kinds = {item.lower() for item in top_focus.interaction_kinds}
    vulnerability_types = {item.lower() for item in top_focus.vulnerability_types}
    return bool(
        "workflow_abuse_candidate" in interaction_kinds
        or {"workflow_bypass", "parameter_tampering"} & vulnerability_types
        or ("workflow_signal" in interaction_kinds and top_focus.workflow_edge_count > 0)
    )


def _top_target_profile_key(target_model: PlannerTargetModelSummary | None) -> str:
    if target_model is None or not target_model.target_profile_hypotheses:
        return ""
    return str(target_model.target_profile_hypotheses[0].key)


def _capability_pressure_score(target_model: PlannerTargetModelSummary | None, *, pack_key: str) -> int:
    if target_model is None:
        return 0
    for pressure in target_model.capability_pressures:
        if pressure.pack_key == pack_key:
            return int(pressure.pressure_score)
    return 0


def _graph_preferred_action_keys(
    target_model: PlannerTargetModelSummary | None,
    *,
    route_group: str,
) -> list[str]:
    if target_model is None:
        return []
    route_group = str(route_group or "").strip()
    primary: list[str] = []
    secondary: list[str] = []
    for pressure in target_model.capability_pressures:
        graph_action_keys = list(pressure.graph_planner_action_keys or [])
        if not graph_action_keys:
            continue
        if route_group and route_group in pressure.top_route_groups:
            primary.extend(graph_action_keys)
        else:
            secondary.extend(graph_action_keys)
    return _dedupe_preserve_order(primary + secondary)


def _graph_rationale(
    target_model: PlannerTargetModelSummary | None,
    *,
    route_group: str,
) -> list[str]:
    if target_model is None:
        return []
    route_group = str(route_group or "").strip()
    primary: list[str] = []
    secondary: list[str] = []
    for pressure in target_model.capability_pressures:
        rationale = list(pressure.graph_rationale or [])
        if not rationale:
            continue
        if route_group and route_group in pressure.top_route_groups:
            primary.extend(rationale)
        else:
            secondary.extend(rationale)
    return _dedupe_preserve_order(primary + secondary)


def _expected_path_change(*, preferred_tool_ids: list[str], suppressed_tool_ids: list[str]) -> str:
    if preferred_tool_ids and suppressed_tool_ids:
        return "rebalance_phase"
    if preferred_tool_ids:
        return "add_dynamic_followups"
    if suppressed_tool_ids:
        return "suppress_low_value_tools"
    return "none"


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


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        text = str(item).strip()
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        deduped.append(text)
    return deduped
