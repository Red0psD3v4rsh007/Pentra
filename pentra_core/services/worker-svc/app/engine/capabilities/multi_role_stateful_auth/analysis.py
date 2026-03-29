"""Multi-role stateful auth capability analysis and candidate generation."""

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
_AUTH_ROUTE_HINTS = ("/login", "/signin", "/register", "/reset", "/forgot", "/whoami", "/auth")
_WORKFLOW_ROUTE_HINTS = ("/cart", "/basket", "/checkout", "/order", "/payment", "/portal")


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text()) or {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"Multi-role auth capability file must contain a YAML object: {path}")
    return payload


@lru_cache(maxsize=1)
def load_multi_role_stateful_auth_capability_manifest() -> dict[str, Any]:
    return _load_yaml(_MANIFEST_PATH)


def build_multi_role_stateful_auth_pack(
    *,
    base_url: str,
    scan_config: dict[str, Any],
    pages: list[dict[str, Any]],
    forms: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    replays: list[dict[str, Any]],
    probe_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    manifest = load_multi_role_stateful_auth_capability_manifest()
    enabled = _stateful_auth_enabled(scan_config)
    target_profile = _infer_target_profile(
        pages=pages,
        workflows=workflows,
        sessions=sessions,
        probe_findings=probe_findings,
    )
    role_matrix = _build_role_matrix(sessions=sessions, pages=pages)
    route_assessments = _build_route_assessments(
        pages=pages,
        forms=forms,
        sessions=sessions,
        workflows=workflows,
        replays=replays,
        probe_findings=probe_findings,
        target_profile=target_profile,
    )
    negative_evidence = [
        _negative_evidence_item(assessment)
        for assessment in route_assessments
        if bool(assessment.get("negative_evidence"))
    ]
    candidates = _build_candidates(
        assessments=route_assessments,
        target_profile=target_profile,
    )
    planner_hooks = _build_planner_hooks(candidates)
    route_assessment_counts = _route_assessment_counts(route_assessments)
    advisory_bundle = _build_ai_advisory_bundle(
        enabled=enabled,
        target_profile=target_profile,
        role_matrix=role_matrix,
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
            "role_matrix": role_matrix,
            "role_count": len(role_matrix),
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


def _stateful_auth_enabled(scan_config: dict[str, Any]) -> bool:
    stateful = scan_config.get("stateful_testing", {})
    if not isinstance(stateful, dict):
        return False
    if "enabled" in stateful and not bool(stateful.get("enabled")):
        return False
    auth = stateful.get("auth", {})
    return isinstance(auth, dict) and bool(auth)


def _infer_target_profile(
    *,
    pages: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
    probe_findings: list[dict[str, Any]],
) -> str:
    route_text = " ".join(
        str(page.get("route_group") or urlparse(str(page.get("url") or "")).path or "").lower()
        for page in pages
        if str(page.get("url") or "").strip()
    )
    if any(hint in route_text for hint in _WORKFLOW_ROUTE_HINTS) or len(workflows) >= 2:
        return "workflow_heavy_commerce"
    if any(hint in route_text for hint in _PRIVILEGED_ROUTE_HINTS) or any(
        str(session.get("auth_state") or "").strip().lower() == "elevated"
        for session in sessions
    ) or any(
        str(finding.get("vulnerability_type") or "").strip().lower() == "privilege_escalation"
        for finding in probe_findings
    ):
        return "auth_heavy_admin_portal"
    return "spa_rest_api"


def _build_role_matrix(
    *,
    sessions: list[dict[str, Any]],
    pages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    page_counts: dict[str, int] = {}
    privileged_counts: dict[str, int] = {}
    api_counts: dict[str, int] = {}
    for page in pages:
        label = str(page.get("session_label") or "").strip()
        if not label:
            continue
        page_counts[label] = page_counts.get(label, 0) + 1
        page_url = str(page.get("url") or "").lower()
        route_group = str(page.get("route_group") or "").lower()
        if any(marker in route_group or marker in page_url for marker in _PRIVILEGED_ROUTE_HINTS):
            privileged_counts[label] = privileged_counts.get(label, 0) + 1
        if any(marker in page_url for marker in ("/api/", "/rest/", "/graphql")):
            api_counts[label] = api_counts.get(label, 0) + 1

    matrix: list[dict[str, Any]] = []
    for session in sessions:
        label = str(session.get("session_label") or "").strip()
        if not label:
            continue
        matrix.append(
            {
                "session_label": label,
                "auth_state": str(session.get("auth_state") or "none"),
                "role": str(session.get("role") or session.get("auth_state") or "anonymous"),
                "auth_method": str(session.get("auth_method") or "unknown"),
                "route_count": int(page_counts.get(label, 0)),
                "privileged_route_count": int(privileged_counts.get(label, 0)),
                "api_route_count": int(api_counts.get(label, 0)),
                "cookie_name_count": len(session.get("cookie_names") or []),
                "landing_url": str(session.get("landing_url") or ""),
            }
        )
    matrix.sort(key=lambda item: (item["auth_state"], item["session_label"]))
    return matrix


def _build_route_assessments(
    *,
    pages: list[dict[str, Any]],
    forms: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    replays: list[dict[str, Any]],
    probe_findings: list[dict[str, Any]],
    target_profile: str,
) -> list[dict[str, Any]]:
    session_states = {
        str(session.get("session_label") or "").strip(): str(session.get("auth_state") or "none")
        for session in sessions
        if str(session.get("session_label") or "").strip()
    }
    grouped: dict[str, dict[str, Any]] = {}

    def ensure(route_group: str) -> dict[str, Any]:
        return grouped.setdefault(
            route_group,
            {
                "route_group": route_group,
                "page_urls": set(),
                "session_labels": set(),
                "auth_states": set(),
                "parameter_names": set(),
                "workflow_edge_count": 0,
                "replay_count": 0,
                "probe_types": set(),
                "requires_auth": False,
                "privileged_surface": False,
                "auth_route": False,
                "route_local_evidence": False,
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
        if any(marker in lowered for marker in _AUTH_ROUTE_HINTS):
            item["auth_route"] = True

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
        item["parameter_names"].update(_string_list(form.get("field_names")))
        item["parameter_names"].update(_string_list(form.get("hidden_field_names")))
        if form.get("requires_auth"):
            item["requires_auth"] = True
        label = str(form.get("session_label") or "").strip()
        if label:
            item["session_labels"].add(label)
            item["auth_states"].add(session_states.get(label, str(form.get("auth_state") or "none")))

    for workflow in workflows:
        route_group = _route_group(str(workflow.get("target_url") or workflow.get("source_url") or ""))
        if not route_group:
            continue
        item = ensure(route_group)
        item["workflow_edge_count"] += 1
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
        if vuln_type in {"auth_bypass", "privilege_escalation", "idor"}:
            item["requires_auth"] = True
        lowered = f"{route_group} {finding.get('endpoint') or finding.get('target') or ''}".lower()
        if any(marker in lowered for marker in _PRIVILEGED_ROUTE_HINTS):
            item["privileged_surface"] = True
        if any(marker in lowered for marker in _AUTH_ROUTE_HINTS):
            item["auth_route"] = True

    assessments: list[dict[str, Any]] = []
    for route_group, item in grouped.items():
        session_labels = _dedupe_strings(sorted(item["session_labels"]))
        auth_states = _dedupe_strings(sorted(item["auth_states"]))
        parameter_names = _dedupe_strings(sorted(item["parameter_names"]))
        probe_types = _dedupe_strings(sorted(item["probe_types"]))
        privileged_surface = bool(item["privileged_surface"])
        auth_route = bool(item["auth_route"])
        route_local_evidence = bool(item["route_local_evidence"])
        role_variant_count = len(session_labels) if session_labels else len(auth_states)

        assessment_state = "low_signal"
        negative_evidence = False
        planner_action = "pressure_auth_tokens_and_login_flows"
        attack_primitive = "session_and_token_abuse_probe"
        workflow_state = "authenticated_surface" if item["requires_auth"] else "anonymous_surface"
        risk_score = 18

        if probe_types:
            assessment_state = "role_differential_candidate"
            planner_action = "compare_role_access"
            attack_primitive = "privileged_api_surface_diff" if privileged_surface else "login_and_reset_flow_mutation_probe"
            workflow_state = "privileged_surface" if privileged_surface else "role_transition_state"
            risk_score = 82
        elif privileged_surface and role_variant_count >= 2:
            assessment_state = "role_differential_candidate"
            planner_action = "enumerate_privileged_api_surface"
            attack_primitive = "privileged_api_surface_diff"
            workflow_state = "privileged_surface"
            risk_score = 68
        elif item["requires_auth"] and role_variant_count >= 2:
            assessment_state = "role_differential_candidate"
            planner_action = "compare_role_access"
            attack_primitive = "login_and_reset_flow_mutation_probe"
            workflow_state = "role_transition_state"
            risk_score = 60
        elif auth_route:
            assessment_state = "auth_transition_pressure"
            planner_action = "pressure_auth_tokens_and_login_flows"
            attack_primitive = "session_and_token_abuse_probe"
            workflow_state = "role_transition_state"
            risk_score = 52
        elif role_variant_count >= 2:
            assessment_state = "converged_behavior"
            planner_action = "compare_role_access"
            attack_primitive = "privileged_api_surface_diff" if privileged_surface else "login_and_reset_flow_mutation_probe"
            workflow_state = "authenticated_surface"
            risk_score = 28
            negative_evidence = True

        risk_score += min(item["workflow_edge_count"], 3) * 4
        risk_score += min(item["replay_count"], 2) * 3
        risk_score += min(len(parameter_names), 3) * 2
        if target_profile == "auth_heavy_admin_portal" and privileged_surface:
            risk_score += 8
        if target_profile == "workflow_heavy_commerce" and item["workflow_edge_count"] > 0:
            risk_score += 6

        evidence_gaps = _evidence_gaps(
            assessment_state=assessment_state,
            role_variant_count=role_variant_count,
            replay_count=int(item["replay_count"]),
            privileged_surface=privileged_surface,
            route_local_evidence=route_local_evidence,
        )
        reasoning = _assessment_reasoning(
            route_group=route_group,
            assessment_state=assessment_state,
            session_labels=session_labels,
            probe_types=probe_types,
            privileged_surface=privileged_surface,
            evidence_gaps=evidence_gaps,
            negative_evidence=negative_evidence,
        )
        assessments.append(
            {
                "route_group": route_group,
                "page_url": sorted(item["page_urls"])[0] if item["page_urls"] else "",
                "assessment_state": assessment_state,
                "risk_score": min(risk_score, 100),
                "advisory_priority": min(risk_score + (12 if assessment_state == "role_differential_candidate" else 0), 100),
                "role_variant_count": role_variant_count,
                "candidate_count": 1 if assessment_state in {"role_differential_candidate", "auth_transition_pressure"} else 0,
                "parameter_hypotheses": parameter_names[:6],
                "proof_contracts": ["role_differential_access_contract"],
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
    assessments: list[dict[str, Any]],
    target_profile: str,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for assessment in assessments:
        state = str(assessment.get("assessment_state") or "")
        if state not in {"role_differential_candidate", "auth_transition_pressure"}:
            continue
        route_group = str(assessment.get("route_group") or "")
        page_url = str(assessment.get("page_url") or "")
        planner_action = str(assessment.get("planner_action") or "")
        candidates.append(
            {
                "candidate_key": f"{route_group}:{state}",
                "request_url": page_url,
                "url": page_url,
                "target": page_url,
                "endpoint": page_url,
                "title": "Multi-role auth capability candidate",
                "severity": "medium" if state == "auth_transition_pressure" else "high",
                "confidence": int(assessment.get("risk_score") or 0),
                "description": str(assessment.get("reasoning") or ""),
                "tool_source": "web_interact",
                "vulnerability_type": "auth_bypass" if planner_action == "pressure_auth_tokens_and_login_flows" else "idor",
                "surface": "web",
                "route_group": route_group,
                "verification_state": "suspected",
                "verification_confidence": int(assessment.get("risk_score") or 0),
                "references": [
                    *[f"role:{label}" for label in assessment.get("session_labels") or []],
                    *[f"probe:{value}" for value in assessment.get("probe_types") or []],
                ],
                "challenge_family": "broken_authentication" if state == "auth_transition_pressure" else "broken_access_control",
                "attack_primitive": assessment.get("attack_primitive"),
                "workflow_state": assessment.get("workflow_state"),
                "workflow_stage": "analysis",
                "planner_action": planner_action,
                "proof_contract": "role_differential_access_contract",
                "target_profile": target_profile,
                "capability_pack": "p3a_multi_role_stateful_auth",
                "triggering_condition": state,
                "route_context": {
                    "session_labels": assessment.get("session_labels") or [],
                    "auth_states": assessment.get("auth_states") or [],
                    "workflow_edge_count": int(assessment.get("workflow_edge_count") or 0),
                },
                "verification_context": {
                    "verify_type": "role_differential_access",
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
                "pack_key": "p3a_multi_role_stateful_auth",
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
        "role_differential_candidate": 0,
        "auth_transition_pressure": 0,
        "converged_behavior": 0,
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
    privileged_surface: bool,
    route_local_evidence: bool,
) -> list[str]:
    gaps: list[str] = []
    if assessment_state == "role_differential_candidate":
        gaps.append("verification")
        if role_variant_count < 2:
            gaps.append("role_coverage")
    elif assessment_state == "auth_transition_pressure":
        gaps.extend(["session_material", "login_flow_comparison"])
    elif assessment_state == "converged_behavior":
        gaps.append("differential_outcome")
    else:
        gaps.append("signal_strength")
    if replay_count == 0:
        gaps.append("replay_context")
    if privileged_surface:
        gaps.append("privileged_surface_validation")
    if not route_local_evidence:
        gaps.append("route_local_evidence")
    return _dedupe_strings(gaps)


def _assessment_reasoning(
    *,
    route_group: str,
    assessment_state: str,
    session_labels: list[str],
    probe_types: list[str],
    privileged_surface: bool,
    evidence_gaps: list[str],
    negative_evidence: bool,
) -> str:
    if probe_types:
        return (
            f"Route {route_group} already has stateful probe evidence ({', '.join(probe_types[:3])}) "
            "and should enter differential replay verification."
        )
    if assessment_state == "role_differential_candidate":
        qualifier = "privileged surface" if privileged_surface else "multi-role route"
        return (
            f"Route {route_group} behaves like a {qualifier} across roles "
            f"({', '.join(session_labels[:3]) or 'unknown'}) and should be compared under replay."
        )
    if assessment_state == "auth_transition_pressure":
        return (
            f"Route {route_group} looks like an auth transition surface and should be pressure-tested "
            "for login, token, or reset-state mistakes."
        )
    if negative_evidence:
        return (
            f"Route {route_group} currently converges across roles and is demoted until stronger differential "
            f"evidence appears. Remaining gaps: {', '.join(evidence_gaps[:3])}."
        )
    return f"Route {route_group} has weak auth differential signal and should be deprioritized."


def _build_ai_advisory_bundle(
    *,
    enabled: bool,
    target_profile: str,
    role_matrix: list[dict[str, Any]],
    route_assessments: list[dict[str, Any]],
    route_assessment_counts: dict[str, int],
) -> dict[str, Any]:
    if not enabled:
        return {
            "enabled": False,
            "advisory_mode": "multi_role_auth_route_focus",
            "prompt_contract": None,
            "focus_routes": [],
            "role_matrix_preview": [],
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
            "evidence_gaps": list(item.get("evidence_gaps") or [])[:4],
            "reasoning": str(item.get("reasoning") or ""),
        }
        for item in route_assessments[:5]
    ]
    role_matrix_preview = [
        {
            "session_label": str(item.get("session_label") or ""),
            "auth_state": str(item.get("auth_state") or ""),
            "role": str(item.get("role") or ""),
            "route_count": int(item.get("route_count") or 0),
            "privileged_route_count": int(item.get("privileged_route_count") or 0),
        }
        for item in role_matrix[:5]
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
        "capability_pack": "p3a_multi_role_stateful_auth",
        "advisory_mode": "multi_role_auth_route_focus",
        "target_profile": target_profile,
        "route_assessment_counts": route_assessment_counts,
        "role_matrix_preview": role_matrix_preview,
        "focus_routes": focus_routes,
        "evidence_gap_summary": evidence_gap_summary,
        "proof_contract_boundary": "advisor_only_no_truth_promotion",
    }
    prompt_contract = advisory_prompt_contract("multi_role_auth_route_focus")
    user_prompt = build_json_user_prompt(
        prompt_contract,
        preamble=(
            "Review the multi-role auth route pressure below and recommend which routes and role comparisons "
            "deserve the next safe replay pass. Do not certify findings or proof. Optimize only for route "
            "ranking, workflow segmentation, and evidence-gap closure."
        ),
        context=context,
    )
    return {
        "enabled": True,
        "advisory_mode": "multi_role_auth_route_focus",
        "prompt_contract": {
            "contract_id": prompt_contract.contract_id,
            "prompt_version": prompt_contract.prompt_version,
            "task_type": prompt_contract.task_type,
            "response_format": prompt_contract.response_format,
        },
        "focus_routes": focus_routes,
        "role_matrix_preview": role_matrix_preview,
        "evidence_gap_summary": evidence_gap_summary,
        "user_prompt": user_prompt,
    }


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
