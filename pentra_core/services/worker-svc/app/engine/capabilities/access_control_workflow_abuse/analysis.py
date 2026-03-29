"""Access-control and workflow-abuse capability analysis and candidate generation."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

import yaml
from pentra_common.ai.prompt_contracts import advisory_prompt_contract, build_json_user_prompt

_CAPABILITY_DIR = Path(__file__).resolve().parent
_MANIFEST_PATH = _CAPABILITY_DIR / "capability_manifest.yaml"

_PRIVILEGED_ROUTE_HINTS = ("/admin", "/manage", "/settings", "/users", "/roles")
_WORKFLOW_ROUTE_HINTS = ("/cart", "/basket", "/checkout", "/order", "/payment", "/portal")
_OBJECT_REFERENCE_HINTS = ("id", "user", "account", "order", "profile", "invoice")
_ACCESS_CONTROL_FINDINGS = {"idor", "auth_bypass", "privilege_escalation"}
_WORKFLOW_FINDINGS = {"workflow_bypass", "parameter_tampering"}


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text()) or {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"Access-control capability file must contain a YAML object: {path}")
    return payload


@lru_cache(maxsize=1)
def load_access_control_workflow_abuse_capability_manifest() -> dict[str, Any]:
    return _load_yaml(_MANIFEST_PATH)


def build_access_control_workflow_abuse_pack(
    *,
    base_url: str,
    scan_config: dict[str, Any],
    pages: list[dict[str, Any]],
    forms: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    replays: list[dict[str, Any]],
    probe_findings: list[dict[str, Any]],
    capability_results: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    manifest = load_access_control_workflow_abuse_capability_manifest()
    auth_summary = _auth_capability_summary(capability_results or {})
    enabled = _pack_enabled(scan_config=scan_config, auth_summary=auth_summary, workflows=workflows, probe_findings=probe_findings)
    target_profile = _infer_target_profile(auth_summary=auth_summary, pages=pages, workflows=workflows)
    route_assessments = _build_route_assessments(
        base_url=base_url,
        pages=pages,
        forms=forms,
        sessions=sessions,
        workflows=workflows,
        replays=replays,
        probe_findings=probe_findings,
        auth_summary=auth_summary,
        target_profile=target_profile,
    )
    negative_evidence = [
        _negative_evidence_item(assessment)
        for assessment in route_assessments
        if bool(assessment.get("negative_evidence"))
    ]
    candidates = _build_candidates(route_assessments=route_assessments, target_profile=target_profile)
    planner_hooks = _build_planner_hooks(candidates)
    route_assessment_counts = _route_assessment_counts(route_assessments)
    advisory_bundle = _build_ai_advisory_bundle(
        enabled=enabled,
        target_profile=target_profile,
        auth_summary=auth_summary,
        route_assessments=route_assessments,
        route_assessment_counts=route_assessment_counts,
    )

    return {
        "capability_summary": {
            "pack_key": manifest["pack_key"],
            "manifest_name": manifest["name"],
            "enabled": enabled,
            "target_profile": target_profile,
            "target_profile_keys": list(manifest.get("target_profile_keys") or []),
            "benchmark_target_keys": list(manifest.get("benchmark_target_keys") or []),
            "challenge_family_keys": list(manifest.get("ontology_family_keys") or []),
            "attack_primitive_keys": list(manifest.get("attack_primitive_keys") or []),
            "proof_contract_keys": list(manifest.get("proof_contract_keys") or []),
            "planner_action_keys": list(manifest.get("planner_action_keys") or []),
            "cheatsheet_category_keys": list(
                ((manifest.get("knowledge_dependencies") or {}).get("cheatsheet_category_keys") or [])
            ),
            "auth_pack_dependency": {
                "pack_key": str(auth_summary.get("pack_key") or ""),
                "candidate_count": int(auth_summary.get("candidate_count") or 0),
                "route_count": len(auth_summary.get("route_assessments") or []),
            },
            "route_assessments": route_assessments,
            "route_assessment_counts": route_assessment_counts,
            "planner_hooks": planner_hooks,
            "planner_hook_count": len(planner_hooks),
            "negative_evidence": negative_evidence,
            "negative_evidence_count": len(negative_evidence),
            "advisory_context": advisory_bundle,
            "ai_advisory_bundle": advisory_bundle,
            "ai_advisory_ready": bool(advisory_bundle.get("enabled")),
            "candidate_count": len(candidates),
        },
        "candidates": candidates,
        "negative_evidence": negative_evidence,
        "advisory_context": advisory_bundle,
    }


def _pack_enabled(
    *,
    scan_config: dict[str, Any],
    auth_summary: dict[str, Any],
    workflows: list[dict[str, Any]],
    probe_findings: list[dict[str, Any]],
) -> bool:
    stateful = scan_config.get("stateful_testing", {})
    if isinstance(stateful, dict) and "enabled" in stateful and not bool(stateful.get("enabled")):
        return False
    return bool(
        auth_summary
        or workflows
        or any(str(item.get("vulnerability_type") or "").strip().lower() in (_ACCESS_CONTROL_FINDINGS | _WORKFLOW_FINDINGS) for item in probe_findings)
    )


def _auth_capability_summary(capability_results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    auth_pack = capability_results.get("p3a_multi_role_stateful_auth")
    if not isinstance(auth_pack, dict):
        return {}
    summary = auth_pack.get("capability_summary")
    return summary if isinstance(summary, dict) else {}


def _infer_target_profile(
    *,
    auth_summary: dict[str, Any],
    pages: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
) -> str:
    target_profile = str(auth_summary.get("target_profile") or "").strip()
    if target_profile:
        return target_profile
    route_text = " ".join(
        str(page.get("route_group") or urlparse(str(page.get("url") or "")).path or "").lower()
        for page in pages
        if str(page.get("url") or "").strip()
    )
    if any(hint in route_text for hint in _WORKFLOW_ROUTE_HINTS) or len(workflows) >= 2:
        return "workflow_heavy_commerce"
    if any(hint in route_text for hint in _PRIVILEGED_ROUTE_HINTS):
        return "auth_heavy_admin_portal"
    return "spa_rest_api"


def _build_route_assessments(
    *,
    base_url: str,
    pages: list[dict[str, Any]],
    forms: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    replays: list[dict[str, Any]],
    probe_findings: list[dict[str, Any]],
    auth_summary: dict[str, Any],
    target_profile: str,
) -> list[dict[str, Any]]:
    session_states = {
        str(session.get("session_label") or "").strip(): str(session.get("auth_state") or "none")
        for session in sessions
        if str(session.get("session_label") or "").strip()
    }
    auth_assessments = {
        str(item.get("route_group") or "").strip(): item
        for item in list(auth_summary.get("route_assessments") or [])
        if isinstance(item, dict) and str(item.get("route_group") or "").strip()
    }
    grouped: dict[str, dict[str, Any]] = {}

    def ensure(route_group: str) -> dict[str, Any]:
        auth_assessment = auth_assessments.get(route_group) or {}
        return grouped.setdefault(
            route_group,
            {
                "route_group": route_group,
                "page_urls": set(_string_list([auth_assessment.get("page_url") or ""])),
                "session_labels": set(_string_list(auth_assessment.get("session_labels"))),
                "auth_states": set(_string_list(auth_assessment.get("auth_states"))),
                "parameter_names": set(_string_list(auth_assessment.get("parameter_hypotheses"))),
                "workflow_edge_count": 0,
                "replay_count": 0,
                "probe_types": set(),
                "requires_auth": bool(auth_assessment.get("requires_auth")),
                "privileged_surface": bool(auth_assessment.get("privileged_surface")),
                "route_local_evidence": bool(auth_assessment),
                "object_reference_hint": False,
                "workflow_signal": False,
                "auth_assessment_state": str(auth_assessment.get("assessment_state") or ""),
                "auth_reasoning": str(auth_assessment.get("reasoning") or ""),
            },
        )

    for page in pages:
        page_url = str(page.get("url") or "").strip()
        if not page_url:
            continue
        route_group = str(page.get("route_group") or _route_group(page_url)).strip() or _route_group(page_url)
        item = ensure(route_group)
        item["page_urls"].add(page_url)
        item["route_local_evidence"] = True
        label = str(page.get("session_label") or "").strip()
        if label:
            item["session_labels"].add(label)
            item["auth_states"].add(session_states.get(label, str(page.get("auth_state") or "none")))
        if page.get("requires_auth"):
            item["requires_auth"] = True
        lowered = f"{route_group} {page_url}".lower()
        if any(marker in lowered for marker in _PRIVILEGED_ROUTE_HINTS):
            item["privileged_surface"] = True
        if any(marker in lowered for marker in _WORKFLOW_ROUTE_HINTS):
            item["workflow_signal"] = True
        if _has_object_reference(route_group=route_group, page_url=page_url):
            item["object_reference_hint"] = True
            item["parameter_names"].update(_query_parameter_names(page_url))

    for form in forms:
        page_url = str(form.get("page_url") or "").strip()
        action_url = str(form.get("action_url") or "").strip()
        route_group = str(form.get("route_group") or _route_group(page_url or action_url)).strip()
        if not route_group:
            continue
        item = ensure(route_group)
        if page_url:
            item["page_urls"].add(page_url)
        if action_url:
            item["page_urls"].add(action_url)
        field_names = _string_list(form.get("field_names")) + _string_list(form.get("hidden_field_names"))
        item["parameter_names"].update(field_names)
        if _field_names_suggest_object_reference(field_names):
            item["object_reference_hint"] = True
        if form.get("requires_auth"):
            item["requires_auth"] = True
        label = str(form.get("session_label") or "").strip()
        if label:
            item["session_labels"].add(label)
            item["auth_states"].add(session_states.get(label, str(form.get("auth_state") or "none")))

    for workflow in workflows:
        route_group = _route_group(str(workflow.get("target_url") or workflow.get("source_url") or base_url))
        if not route_group:
            continue
        item = ensure(route_group)
        item["workflow_edge_count"] += 1
        item["workflow_signal"] = True
        label = str(workflow.get("session_label") or "").strip()
        if label:
            item["session_labels"].add(label)
            item["auth_states"].add(session_states.get(label, "none"))

    for replay in replays:
        route_group = _route_group(str(replay.get("target_url") or ""))
        if not route_group:
            continue
        item = ensure(route_group)
        item["replay_count"] += 1
        label = str(replay.get("session_label") or "").strip()
        if label:
            item["session_labels"].add(label)
            item["auth_states"].add(session_states.get(label, "none"))

    for finding in probe_findings:
        route_group = str(finding.get("route_group") or _route_group(str(finding.get("endpoint") or finding.get("target") or ""))).strip()
        if not route_group:
            continue
        item = ensure(route_group)
        vuln_type = str(finding.get("vulnerability_type") or "").strip().lower()
        if vuln_type:
            item["probe_types"].add(vuln_type)
        if vuln_type in _ACCESS_CONTROL_FINDINGS:
            item["requires_auth"] = True
        if vuln_type in _WORKFLOW_FINDINGS:
            item["workflow_signal"] = True
        endpoint = str(finding.get("endpoint") or finding.get("target") or "")
        if endpoint:
            item["page_urls"].add(endpoint)
            if _has_object_reference(route_group=route_group, page_url=endpoint):
                item["object_reference_hint"] = True
                item["parameter_names"].update(_query_parameter_names(endpoint))
        lowered = f"{route_group} {endpoint}".lower()
        if any(marker in lowered for marker in _PRIVILEGED_ROUTE_HINTS):
            item["privileged_surface"] = True
        if any(marker in lowered for marker in _WORKFLOW_ROUTE_HINTS):
            item["workflow_signal"] = True

    assessments: list[dict[str, Any]] = []
    for route_group, item in grouped.items():
        session_labels = _dedupe_strings(sorted(item["session_labels"]))
        auth_states = _dedupe_strings(sorted(item["auth_states"]))
        parameter_names = _dedupe_strings(sorted(item["parameter_names"]))
        probe_types = _dedupe_strings(sorted(item["probe_types"]))
        role_variant_count = len(session_labels) if session_labels else len(auth_states)
        privileged_surface = bool(item["privileged_surface"])
        workflow_signal = bool(item["workflow_signal"] or item["workflow_edge_count"] > 0)
        object_reference_hint = bool(item["object_reference_hint"])

        assessment_state = "low_signal"
        planner_action = "compare_role_access"
        attack_primitive = "idor_role_diff_probe"
        workflow_state = "authenticated_surface" if item["requires_auth"] else "anonymous_surface"
        proof_contracts = ["role_differential_access_contract"]
        candidate_vulnerability_types: list[str] = []
        negative_evidence = False
        risk_score = 18

        if probe_types and any(value in _WORKFLOW_FINDINGS for value in probe_types):
            assessment_state = "workflow_abuse_candidate"
            planner_action = "mutate_business_workflows"
            attack_primitive = "business_workflow_mutation_probe"
            workflow_state = _workflow_state(route_group)
            proof_contracts = ["role_differential_access_contract", "sensitive_data_exposure_replay"]
            candidate_vulnerability_types = [value for value in probe_types if value in _WORKFLOW_FINDINGS] or ["workflow_bypass"]
            risk_score = 80
        elif probe_types and any(value in _ACCESS_CONTROL_FINDINGS for value in probe_types):
            assessment_state = "access_control_candidate"
            planner_action = "enumerate_privileged_api_surface" if privileged_surface else "compare_role_access"
            attack_primitive = "privileged_api_surface_diff" if privileged_surface else "idor_role_diff_probe"
            workflow_state = "privileged_surface" if privileged_surface else "role_transition_state"
            candidate_vulnerability_types = [value for value in probe_types if value in _ACCESS_CONTROL_FINDINGS]
            risk_score = 78
        elif workflow_signal and (
            target_profile == "workflow_heavy_commerce"
            or str(item["auth_assessment_state"]) in {"role_differential_candidate", "auth_transition_pressure"}
        ):
            assessment_state = "workflow_abuse_candidate"
            planner_action = "mutate_business_workflows"
            attack_primitive = "business_workflow_mutation_probe"
            workflow_state = _workflow_state(route_group)
            proof_contracts = ["role_differential_access_contract", "sensitive_data_exposure_replay"]
            candidate_vulnerability_types = ["workflow_bypass"]
            risk_score = 64
        elif privileged_surface and (
            role_variant_count >= 2 or str(item["auth_assessment_state"]) == "role_differential_candidate"
        ):
            assessment_state = "access_control_candidate"
            planner_action = "enumerate_privileged_api_surface"
            attack_primitive = "privileged_api_surface_diff"
            workflow_state = "privileged_surface"
            candidate_vulnerability_types = ["privilege_escalation"]
            risk_score = 62
        elif object_reference_hint and (
            role_variant_count >= 2 or str(item["auth_assessment_state"]) == "role_differential_candidate"
        ):
            assessment_state = "access_control_candidate"
            planner_action = "compare_role_access"
            attack_primitive = "idor_role_diff_probe"
            workflow_state = "role_transition_state"
            candidate_vulnerability_types = ["idor"]
            risk_score = 58
        elif str(item["auth_assessment_state"]) == "converged_behavior" and role_variant_count >= 2:
            assessment_state = "contradictory_evidence"
            planner_action = "compare_role_access"
            attack_primitive = "idor_role_diff_probe"
            workflow_state = "authenticated_surface"
            candidate_vulnerability_types = []
            negative_evidence = True
            risk_score = 24

        risk_score += min(item["workflow_edge_count"], 3) * 4
        risk_score += min(item["replay_count"], 2) * 3
        risk_score += min(len(parameter_names), 3) * 2
        if object_reference_hint:
            risk_score += 8
        if privileged_surface:
            risk_score += 6
        if target_profile == "workflow_heavy_commerce" and workflow_signal:
            risk_score += 8

        evidence_gaps = _evidence_gaps(
            assessment_state=assessment_state,
            role_variant_count=role_variant_count,
            replay_count=int(item["replay_count"]),
            workflow_signal=workflow_signal,
            object_reference_hint=object_reference_hint,
            route_local_evidence=bool(item["route_local_evidence"]),
        )
        reasoning = _assessment_reasoning(
            route_group=route_group,
            assessment_state=assessment_state,
            probe_types=probe_types,
            session_labels=session_labels,
            privileged_surface=privileged_surface,
            workflow_signal=workflow_signal,
            evidence_gaps=evidence_gaps,
            negative_evidence=negative_evidence,
            auth_reasoning=str(item["auth_reasoning"] or ""),
        )
        assessments.append(
            {
                "route_group": route_group,
                "page_url": sorted(item["page_urls"])[0] if item["page_urls"] else "",
                "assessment_state": assessment_state,
                "risk_score": min(risk_score, 100),
                "advisory_priority": min(risk_score + (10 if assessment_state != "low_signal" else 0), 100),
                "role_variant_count": role_variant_count,
                "candidate_count": 1 if assessment_state in {"access_control_candidate", "workflow_abuse_candidate"} else 0,
                "parameter_hypotheses": parameter_names[:8],
                "proof_contracts": proof_contracts,
                "planner_action": planner_action,
                "attack_primitive": attack_primitive,
                "workflow_state": workflow_state,
                "session_labels": session_labels,
                "auth_states": auth_states,
                "requires_auth": bool(item["requires_auth"]),
                "privileged_surface": privileged_surface,
                "probe_types": probe_types,
                "workflow_edge_count": int(item["workflow_edge_count"]),
                "replay_count": int(item["replay_count"]),
                "workflow_signal": workflow_signal,
                "object_reference_hint": object_reference_hint,
                "candidate_vulnerability_types": candidate_vulnerability_types,
                "negative_evidence": negative_evidence,
                "evidence_gaps": evidence_gaps,
                "next_action": planner_action,
                "reasoning": reasoning,
            }
        )

    assessments.sort(
        key=lambda item: (
            -int(item.get("advisory_priority") or 0),
            -int(item.get("risk_score") or 0),
            str(item.get("route_group") or ""),
        )
    )
    return assessments


def _build_candidates(
    *,
    route_assessments: list[dict[str, Any]],
    target_profile: str,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for assessment in route_assessments:
        state = str(assessment.get("assessment_state") or "")
        if state not in {"access_control_candidate", "workflow_abuse_candidate"}:
            continue
        route_group = str(assessment.get("route_group") or "")
        page_url = str(assessment.get("page_url") or "")
        vulnerability_types = _string_list(assessment.get("candidate_vulnerability_types")) or ["idor"]
        planner_action = str(assessment.get("planner_action") or "")
        proof_contracts = _string_list(assessment.get("proof_contracts"))
        challenge_family = "business_logic_abuse" if state == "workflow_abuse_candidate" else "broken_access_control"
        candidates.append(
            {
                "candidate_key": f"{route_group}:{state}",
                "request_url": page_url,
                "url": page_url,
                "target": page_url,
                "endpoint": page_url,
                "title": "Access-control and workflow-abuse capability candidate",
                "severity": "high" if state == "access_control_candidate" else "medium",
                "confidence": int(assessment.get("risk_score") or 0),
                "description": str(assessment.get("reasoning") or ""),
                "tool_source": "web_interact",
                "vulnerability_type": vulnerability_types[0],
                "surface": "web",
                "route_group": route_group,
                "verification_state": "suspected",
                "verification_confidence": int(assessment.get("risk_score") or 0),
                "references": [
                    *[f"role:{label}" for label in assessment.get("session_labels") or []],
                    *[f"probe:{value}" for value in assessment.get("probe_types") or []],
                ],
                "challenge_family": challenge_family,
                "attack_primitive": assessment.get("attack_primitive"),
                "workflow_state": assessment.get("workflow_state"),
                "workflow_stage": "analysis",
                "planner_action": planner_action,
                "proof_contract": proof_contracts[0] if proof_contracts else "role_differential_access_contract",
                "target_profile": target_profile,
                "capability_pack": "p3a_access_control_workflow_abuse",
                "triggering_condition": state,
                "route_context": {
                    "session_labels": assessment.get("session_labels") or [],
                    "auth_states": assessment.get("auth_states") or [],
                    "workflow_edge_count": int(assessment.get("workflow_edge_count") or 0),
                    "workflow_signal": bool(assessment.get("workflow_signal")),
                    "object_reference_hint": bool(assessment.get("object_reference_hint")),
                },
                "verification_context": {
                    "verify_type": "workflow_mutation_replay" if state == "workflow_abuse_candidate" else "role_differential_access",
                    "route_group": route_group,
                    "page_url": page_url,
                    "planner_action": planner_action,
                    "session_labels": assessment.get("session_labels") or [],
                    "auth_states": assessment.get("auth_states") or [],
                    "parameter_hypotheses": assessment.get("parameter_hypotheses") or [],
                },
            }
        )
    return candidates


def _build_planner_hooks(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hooks: list[dict[str, Any]] = []
    seen: set[str] = set()
    for candidate in candidates:
        route_group = str(candidate.get("route_group") or "").strip()
        planner_action = str(candidate.get("planner_action") or "").strip()
        key = f"{route_group}:{planner_action}"
        if not route_group or not planner_action or key in seen:
            continue
        seen.add(key)
        hooks.append(
            {
                "pack_key": "p3a_access_control_workflow_abuse",
                "route_group": route_group,
                "planner_action": planner_action,
                "target_url": str(candidate.get("request_url") or candidate.get("url") or ""),
                "proof_contract": str(candidate.get("proof_contract") or ""),
                "attack_primitive": str(candidate.get("attack_primitive") or ""),
                "target_profile": str(candidate.get("target_profile") or ""),
            }
        )
    return hooks


def _route_assessment_counts(route_assessments: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "access_control_candidate": 0,
        "workflow_abuse_candidate": 0,
        "contradictory_evidence": 0,
        "low_signal": 0,
        "negative_evidence_routes": 0,
    }
    for assessment in route_assessments:
        state = str(assessment.get("assessment_state") or "").strip()
        if state in counts:
            counts[state] += 1
        if bool(assessment.get("negative_evidence")):
            counts["negative_evidence_routes"] += 1
    return counts


def _negative_evidence_item(assessment: dict[str, Any]) -> dict[str, Any]:
    return {
        "route_group": str(assessment.get("route_group") or ""),
        "assessment_state": str(assessment.get("assessment_state") or ""),
        "reasoning": str(assessment.get("reasoning") or ""),
        "session_labels": list(assessment.get("session_labels") or []),
        "auth_states": list(assessment.get("auth_states") or []),
        "evidence_gaps": list(assessment.get("evidence_gaps") or []),
    }


def _evidence_gaps(
    *,
    assessment_state: str,
    role_variant_count: int,
    replay_count: int,
    workflow_signal: bool,
    object_reference_hint: bool,
    route_local_evidence: bool,
) -> list[str]:
    gaps: list[str] = []
    if assessment_state == "access_control_candidate":
        gaps.append("verification")
        if role_variant_count < 2:
            gaps.append("role_coverage")
        if object_reference_hint:
            gaps.append("object_reference_replay")
    elif assessment_state == "workflow_abuse_candidate":
        gaps.extend(["workflow_sequence_replay", "verification"])
        if role_variant_count < 2:
            gaps.append("role_coverage")
    elif assessment_state == "contradictory_evidence":
        gaps.append("differential_outcome")
    else:
        gaps.append("signal_strength")
    if replay_count == 0:
        gaps.append("replay_context")
    if workflow_signal:
        gaps.append("workflow_checkpoint")
    if not route_local_evidence:
        gaps.append("route_local_evidence")
    return _dedupe_strings(gaps)


def _assessment_reasoning(
    *,
    route_group: str,
    assessment_state: str,
    probe_types: list[str],
    session_labels: list[str],
    privileged_surface: bool,
    workflow_signal: bool,
    evidence_gaps: list[str],
    negative_evidence: bool,
    auth_reasoning: str,
) -> str:
    if probe_types:
        return (
            f"Route {route_group} already has stateful evidence ({', '.join(probe_types[:3])}) "
            "and should enter differential replay rather than generic scanning."
        )
    if assessment_state == "access_control_candidate":
        qualifier = "privileged surface" if privileged_surface else "object-level access path"
        return (
            f"Route {route_group} behaves like a {qualifier} across roles "
            f"({', '.join(session_labels[:3]) or 'unknown'}) and should be replayed comparatively."
        )
    if assessment_state == "workflow_abuse_candidate":
        return (
            f"Route {route_group} sits inside a mutable workflow path and should be replayed with "
            "step-order, repeat, or object-reference mutations."
        )
    if negative_evidence:
        return (
            f"Route {route_group} currently converges under available role/workflow evidence and is demoted. "
            f"Remaining gaps: {', '.join(evidence_gaps[:3])}."
        )
    if auth_reasoning:
        return auth_reasoning
    if workflow_signal:
        return f"Route {route_group} has workflow pressure but not enough replayable divergence yet."
    return f"Route {route_group} has weak access-control/workflow signal and should be deprioritized."


def _build_ai_advisory_bundle(
    *,
    enabled: bool,
    target_profile: str,
    auth_summary: dict[str, Any],
    route_assessments: list[dict[str, Any]],
    route_assessment_counts: dict[str, int],
) -> dict[str, Any]:
    if not enabled:
        return {
            "enabled": False,
            "advisory_mode": "access_control_workflow_focus",
            "prompt_contract": None,
            "focus_routes": [],
            "auth_support_preview": [],
            "evidence_gap_summary": [],
            "user_prompt": "",
        }

    focus_routes = [
        {
            "route_group": str(item.get("route_group") or ""),
            "assessment_state": str(item.get("assessment_state") or ""),
            "risk_score": int(item.get("risk_score") or 0),
            "advisory_priority": int(item.get("advisory_priority") or 0),
            "session_labels": list(item.get("session_labels") or [])[:4],
            "planner_action": str(item.get("planner_action") or ""),
            "candidate_vulnerability_types": list(item.get("candidate_vulnerability_types") or [])[:4],
            "evidence_gaps": list(item.get("evidence_gaps") or [])[:4],
            "reasoning": str(item.get("reasoning") or ""),
        }
        for item in route_assessments[:5]
    ]
    auth_support_preview = [
        {
            "route_group": str(item.get("route_group") or ""),
            "assessment_state": str(item.get("assessment_state") or ""),
            "planner_action": str(item.get("planner_action") or ""),
        }
        for item in list(auth_summary.get("route_assessments") or [])[:5]
        if isinstance(item, dict)
    ]
    evidence_gap_summary = _dedupe_strings(
        [
            gap
            for item in focus_routes
            for gap in item.get("evidence_gaps") or []
            if str(gap).strip()
        ]
    )
    context = {
        "capability_pack": "p3a_access_control_workflow_abuse",
        "advisory_mode": "access_control_workflow_focus",
        "target_profile": target_profile,
        "route_assessment_counts": route_assessment_counts,
        "auth_support_preview": auth_support_preview,
        "focus_routes": focus_routes,
        "evidence_gap_summary": evidence_gap_summary,
        "proof_contract_boundary": "advisor_only_no_truth_promotion",
    }
    prompt_contract = advisory_prompt_contract("access_control_workflow_focus")
    user_prompt = build_json_user_prompt(
        prompt_contract,
        preamble=(
            "Review the access-control and workflow-abuse route pressure below and recommend which routes, "
            "role comparisons, and workflow checkpoints deserve the next bounded replay pass. Do not certify "
            "findings or proof. Optimize only for route ranking, workflow segmentation, and evidence-gap closure."
        ),
        context=context,
    )
    return {
        "enabled": True,
        "advisory_mode": "access_control_workflow_focus",
        "prompt_contract": {
            "contract_id": prompt_contract.contract_id,
            "prompt_version": prompt_contract.prompt_version,
            "task_type": prompt_contract.task_type,
            "response_format": prompt_contract.response_format,
        },
        "focus_routes": focus_routes,
        "auth_support_preview": auth_support_preview,
        "evidence_gap_summary": evidence_gap_summary,
        "user_prompt": user_prompt,
    }


def _workflow_state(route_group: str) -> str:
    lowered = route_group.lower()
    if any(marker in lowered for marker in ("/cart", "/basket", "/checkout", "/order", "/payment")):
        return "basket_checkout_workflow"
    if any(marker in lowered for marker in ("/account", "/profile", "/password", "/settings")):
        return "account_management_workflow"
    return "authenticated_surface"


def _has_object_reference(*, route_group: str, page_url: str) -> bool:
    lowered = f"{route_group} {page_url}".lower()
    if "{id}" in route_group:
        return True
    for key, _value in parse_qsl(urlparse(page_url).query, keep_blank_values=True):
        if key and any(token in key.lower() for token in _OBJECT_REFERENCE_HINTS):
            return True
    return any(segment in lowered for segment in ("/user/", "/users/", "/order/", "/orders/", "/account/", "/profile/"))


def _field_names_suggest_object_reference(field_names: list[str]) -> bool:
    return any(
        any(token in name.lower() for token in _OBJECT_REFERENCE_HINTS)
        for name in field_names
        if str(name).strip()
    )


def _query_parameter_names(url: str) -> list[str]:
    return _dedupe_strings([name for name, _value in parse_qsl(urlparse(url).query, keep_blank_values=True) if name])


def _route_group(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    path = path if path.startswith("/") else f"/{path}"
    segments: list[str] = []
    for segment in path.split("/"):
        if not segment:
            continue
        if segment.isdigit():
            segments.append("{id}")
        else:
            segments.append(segment)
    return "/" + "/".join(segments) if segments else "/"


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    items: list[str] = []
    for value in values:
        text = str(value).strip()
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        items.append(text)
    return items


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return _dedupe_strings([str(item) for item in value])
