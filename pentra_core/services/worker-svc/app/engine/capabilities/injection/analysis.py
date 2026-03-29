"""Injection capability analysis and candidate generation."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

import yaml
from pentra_common.ai.prompt_contracts import advisory_prompt_contract, build_json_user_prompt

_CAPABILITY_DIR = Path(__file__).resolve().parent
_MANIFEST_PATH = _CAPABILITY_DIR / "capability_manifest.yaml"

_API_ROUTE_HINTS = ("/api/", "/rest/")
_GRAPHQL_HINTS = ("/graphql", "graphql", "__schema", "query ", "mutation ")
_GRAPHQL_OPERATION_HINTS = ("query", "variables", "operationname")
_SQL_ERROR_MARKERS = (
    "sql syntax",
    "mysql",
    "sqlite",
    "postgres",
    "syntax error at or near",
    "ora-",
    "odbc",
    "unclosed quotation mark",
)
_JSON_QUERY_HINTS = ("filter", "query", "where", "selector", "search", "sort", "order")
_FORM_QUERY_HINTS = ("search", "query", "q", "filter", "sort", "id", "user", "email")


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text()) or {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"Injection capability file must contain a YAML object: {path}")
    return payload


@lru_cache(maxsize=1)
def load_injection_capability_manifest() -> dict[str, Any]:
    return _load_yaml(_MANIFEST_PATH)


def build_injection_pack(
    *,
    base_url: str,
    scan_config: dict[str, Any],
    pages: list[dict[str, Any]],
    forms: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
    replays: list[dict[str, Any]],
    probe_findings: list[dict[str, Any]],
    capability_results: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    manifest = load_injection_capability_manifest()
    target_profile = _infer_target_profile(pages=pages, forms=forms, replays=replays)
    enabled = _injection_enabled(scan_config=scan_config, pages=pages, forms=forms, replays=replays)
    route_assessments = _build_route_assessments(
        base_url=base_url,
        pages=pages,
        forms=forms,
        sessions=sessions,
        replays=replays,
        probe_findings=probe_findings,
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


def _injection_enabled(
    *,
    scan_config: dict[str, Any],
    pages: list[dict[str, Any]],
    forms: list[dict[str, Any]],
    replays: list[dict[str, Any]],
) -> bool:
    stateful = scan_config.get("stateful_testing", {})
    if isinstance(stateful, dict) and "enabled" in stateful and not bool(stateful.get("enabled")):
        return False
    return bool(pages or forms or replays)


def _infer_target_profile(
    *,
    pages: list[dict[str, Any]],
    forms: list[dict[str, Any]],
    replays: list[dict[str, Any]],
) -> str:
    route_text = " ".join(
        f"{page.get('route_group') or ''} {page.get('url') or ''} {page.get('response_preview') or ''}".lower()
        for page in pages
        if isinstance(page, dict)
    )
    if any(marker in route_text for marker in _GRAPHQL_HINTS):
        return "graphql_heavy_application"
    if forms and not any(marker in route_text for marker in _API_ROUTE_HINTS):
        return "traditional_server_rendered"
    if replays or any(marker in route_text for marker in _API_ROUTE_HINTS):
        return "spa_rest_api"
    return "traditional_server_rendered"


def _build_route_assessments(
    *,
    base_url: str,
    pages: list[dict[str, Any]],
    forms: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
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
                "form_methods": set(),
                "replay_count": 0,
                "api_surface": False,
                "json_surface": False,
                "graphql_surface": False,
                "graphql_endpoint": False,
                "graphql_introspection_exposed": False,
                "graphql_request_template": None,
                "sql_error_markers": set(),
                "query_shape_hints": set(),
                "route_local_evidence": False,
                "requires_auth": False,
                "probe_types": set(),
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
        item["parameter_names"].update(_query_parameter_names(page_url))
        item["query_shape_hints"].update(_query_shape_hints(_query_parameter_names(page_url)))
        label = str(page.get("session_label") or "").strip()
        if label:
            item["session_labels"].add(label)
            item["auth_states"].add(session_states.get(label, str(page.get("auth_state") or "none")))
        if page.get("requires_auth"):
            item["requires_auth"] = True

        lowered = f"{route_group} {page_url}".lower()
        content_type = str(page.get("content_type") or "").lower()
        preview = str(page.get("response_preview") or "").lower()
        if any(marker in lowered for marker in _API_ROUTE_HINTS):
            item["api_surface"] = True
        if "json" in content_type or preview.startswith("{") or preview.startswith("["):
            item["json_surface"] = True
        if any(marker in lowered or marker in preview for marker in _GRAPHQL_HINTS):
            item["graphql_surface"] = True
        if _looks_like_graphql_endpoint(route_group=route_group, page_url=page_url):
            item["graphql_endpoint"] = True
        if item["graphql_endpoint"] and "__schema" in preview:
            item["graphql_introspection_exposed"] = True
        if item["graphql_endpoint"] and item["graphql_request_template"] is None:
            item["graphql_request_template"] = _graphql_request_template(route_group=route_group)
            item["query_shape_hints"].update(_GRAPHQL_OPERATION_HINTS)
        item["sql_error_markers"].update(_sql_error_markers(preview))

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
            item["parameter_names"].update(_query_parameter_names(action_url))
        field_names = _string_list(form.get("field_names")) + _string_list(form.get("hidden_field_names"))
        item["parameter_names"].update(field_names)
        item["query_shape_hints"].update(_query_shape_hints(field_names))
        if _looks_like_graphql_endpoint(route_group=route_group, page_url=action_url or page_url):
            item["graphql_surface"] = True
            item["graphql_endpoint"] = True
            item["graphql_request_template"] = item["graphql_request_template"] or _graphql_request_template(
                route_group=route_group
            )
            item["query_shape_hints"].update(_GRAPHQL_OPERATION_HINTS)
        method = str(form.get("method") or "GET").strip().upper()
        if method:
            item["form_methods"].add(method)
        label = str(form.get("session_label") or "").strip()
        if label:
            item["session_labels"].add(label)
            item["auth_states"].add(session_states.get(label, str(form.get("auth_state") or "none")))
        if form.get("requires_auth"):
            item["requires_auth"] = True

    for replay in replays:
        route_group = _route_group(str(replay.get("target_url") or ""))
        if not route_group:
            continue
        item = ensure(route_group)
        item["replay_count"] += 1
        replay_target = str(replay.get("target_url") or "").strip()
        if _looks_like_graphql_endpoint(route_group=route_group, page_url=replay_target):
            item["graphql_surface"] = True
            item["graphql_endpoint"] = True
            item["graphql_request_template"] = item["graphql_request_template"] or _graphql_request_template(
                route_group=route_group
            )
            item["query_shape_hints"].update(_GRAPHQL_OPERATION_HINTS)
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
        text = " ".join(
            part for part in (
                str(finding.get("description") or ""),
                str(finding.get("response") or ""),
                str(finding.get("exploit_result") or ""),
            )
            if part
        ).lower()
        item["sql_error_markers"].update(_sql_error_markers(text))
        if "graphql_introspection" in vuln_type or ("__schema" in text and "graphql" in text):
            item["graphql_surface"] = True
            item["graphql_introspection_exposed"] = True
        if item["graphql_surface"] and item["graphql_request_template"] is None and item["graphql_endpoint"]:
            item["graphql_request_template"] = _graphql_request_template(route_group=route_group)

    assessments: list[dict[str, Any]] = []
    for route_group, item in grouped.items():
        session_labels = _dedupe_strings(sorted(item["session_labels"]))
        auth_states = _dedupe_strings(sorted(item["auth_states"]))
        parameter_names = _dedupe_strings(sorted(item["parameter_names"]))
        query_shape_hints = _dedupe_strings(sorted(item["query_shape_hints"]))
        probe_types = _dedupe_strings(sorted(item["probe_types"]))
        sql_error_markers = _dedupe_strings(sorted(item["sql_error_markers"]))
        graphql_request_template = item["graphql_request_template"]
        graphql_template_available = isinstance(graphql_request_template, dict) and bool(graphql_request_template)

        assessment_state = "low_signal"
        planner_action = "verify_suspected_injection"
        attack_primitive = "sql_injection_parameter_diff"
        candidate_vulnerability_types: list[str] = []
        negative_evidence = False
        risk_score = 16

        replay_ready = bool(item["replay_count"] > 0 or item["form_methods"] or parameter_names or graphql_template_available)
        if sql_error_markers and parameter_names and replay_ready:
            assessment_state = "injection_candidate"
            attack_primitive = "sql_injection_parameter_diff"
            candidate_vulnerability_types = ["sql_injection"]
            risk_score = 78
        elif bool(item["graphql_surface"]) and replay_ready:
            assessment_state = "graphql_candidate"
            attack_primitive = "nosql_and_graphql_injection_probe"
            candidate_vulnerability_types = (
                ["graphql_introspection", "graphql_injection"]
                if bool(item["graphql_introspection_exposed"])
                else ["graphql_injection"]
            )
            risk_score = 84 if bool(item["graphql_introspection_exposed"]) else 72
        elif bool(item["json_surface"] or item["api_surface"]) and query_shape_hints and replay_ready:
            assessment_state = "injection_candidate"
            attack_primitive = "nosql_and_graphql_injection_probe"
            candidate_vulnerability_types = ["nosql_injection" if item["json_surface"] else "sql_injection"]
            risk_score = 61
        elif parameter_names and replay_ready:
            assessment_state = "injection_candidate"
            attack_primitive = "sql_injection_parameter_diff"
            candidate_vulnerability_types = ["sql_injection"]
            risk_score = 54
        elif parameter_names or sql_error_markers or bool(item["graphql_surface"]):
            assessment_state = "heuristic_only"
            attack_primitive = "nosql_and_graphql_injection_probe" if item["graphql_surface"] else "sql_injection_parameter_diff"
            candidate_vulnerability_types = (
                ["graphql_introspection", "graphql_injection"]
                if item["graphql_surface"] and bool(item["graphql_introspection_exposed"])
                else ["graphql_injection"] if item["graphql_surface"] else ["sql_injection"]
            )
            risk_score = 28
            negative_evidence = not replay_ready

        risk_score += min(len(parameter_names), 4) * 4
        risk_score += min(item["replay_count"], 2) * 5
        risk_score += min(len(sql_error_markers), 2) * 8
        if item["graphql_surface"]:
            risk_score += 10
        if item["api_surface"]:
            risk_score += 4
        if target_profile == "graphql_heavy_application" and item["graphql_surface"]:
            risk_score += 8

        evidence_gaps = _evidence_gaps(
            assessment_state=assessment_state,
            replay_count=int(item["replay_count"]),
            has_parameters=bool(parameter_names),
            graphql_surface=bool(item["graphql_surface"]),
            graphql_template_available=graphql_template_available,
            route_local_evidence=bool(item["route_local_evidence"]),
        )
        reasoning = _assessment_reasoning(
            route_group=route_group,
            assessment_state=assessment_state,
            parameter_names=parameter_names,
            sql_error_markers=sql_error_markers,
            graphql_surface=bool(item["graphql_surface"]),
            graphql_introspection_exposed=bool(item["graphql_introspection_exposed"]),
            evidence_gaps=evidence_gaps,
            negative_evidence=negative_evidence,
        )

        assessments.append(
            {
                "route_group": route_group,
                "page_url": sorted(item["page_urls"])[0] if item["page_urls"] else "",
                "assessment_state": assessment_state,
                "risk_score": min(risk_score, 100),
                "advisory_priority": min(risk_score + (10 if assessment_state in {"injection_candidate", "graphql_candidate"} else 0), 100),
                "candidate_count": 1 if assessment_state in {"injection_candidate", "graphql_candidate"} else 0,
                "parameter_hypotheses": parameter_names[:8],
                "query_shape_hints": query_shape_hints[:6],
                "proof_contracts": ["injection_replay_contract"],
                "planner_action": planner_action,
                "attack_primitive": attack_primitive,
                "session_labels": session_labels,
                "auth_states": auth_states,
                "requires_auth": bool(item["requires_auth"]),
                "api_surface": bool(item["api_surface"]),
                "json_surface": bool(item["json_surface"]),
                "graphql_surface": bool(item["graphql_surface"]),
                "graphql_introspection_exposed": bool(item["graphql_introspection_exposed"]),
                "request_template_available": graphql_template_available,
                "sql_error_markers": sql_error_markers,
                "replay_count": int(item["replay_count"]),
                "negative_evidence": negative_evidence,
                "candidate_vulnerability_types": candidate_vulnerability_types,
                "evidence_gaps": evidence_gaps,
                "next_action": planner_action,
                "reasoning": reasoning,
                "request_template": graphql_request_template if graphql_template_available else None,
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
        if state not in {"injection_candidate", "graphql_candidate"}:
            continue
        route_group = str(assessment.get("route_group") or "")
        page_url = str(assessment.get("page_url") or "")
        candidate_types = _string_list(assessment.get("candidate_vulnerability_types")) or ["sql_injection"]
        attack_primitive = str(assessment.get("attack_primitive") or "")
        for vulnerability_type in candidate_types:
            candidates.append(
                {
                    "candidate_key": f"{route_group}:{state}:{vulnerability_type}",
                    "request_url": page_url,
                    "url": page_url,
                    "target": page_url,
                    "endpoint": page_url,
                    "title": "Injection capability candidate",
                    "severity": "medium",
                    "confidence": int(assessment.get("risk_score") or 0),
                    "description": str(assessment.get("reasoning") or ""),
                    "tool_source": "web_interact",
                    "vulnerability_type": vulnerability_type,
                    "surface": "api" if bool(assessment.get("api_surface") or assessment.get("graphql_surface")) else "web",
                    "route_group": route_group,
                    "verification_state": "suspected",
                    "verification_confidence": int(assessment.get("risk_score") or 0),
                    "references": [
                        *[f"param:{name}" for name in assessment.get("parameter_hypotheses") or []][:6],
                        *[f"signal:{name}" for name in assessment.get("sql_error_markers") or []][:3],
                        *(
                            ["signal:graphql_introspection"]
                            if bool(assessment.get("graphql_introspection_exposed"))
                            else []
                        ),
                    ],
                    "challenge_family": "injection",
                    "attack_primitive": attack_primitive,
                    "workflow_state": "authenticated_surface" if bool(assessment.get("requires_auth")) else "anonymous_surface",
                    "workflow_stage": "analysis",
                    "planner_action": "verify_suspected_injection",
                    "proof_contract": "injection_replay_contract",
                    "target_profile": target_profile,
                    "capability_pack": "p3a_injection",
                    "triggering_condition": state,
                    "route_context": {
                        "session_labels": assessment.get("session_labels") or [],
                        "auth_states": assessment.get("auth_states") or [],
                        "api_surface": bool(assessment.get("api_surface")),
                        "graphql_surface": bool(assessment.get("graphql_surface")),
                        "replay_count": int(assessment.get("replay_count") or 0),
                    },
                    "verification_context": {
                        "verify_type": "injection_replay",
                        "route_group": route_group,
                        "page_url": page_url,
                        "attack_primitive": attack_primitive,
                        "parameter_hypotheses": assessment.get("parameter_hypotheses") or [],
                        "query_shape_hints": assessment.get("query_shape_hints") or [],
                        "graphql_surface": bool(assessment.get("graphql_surface")),
                        "request_template_available": bool(assessment.get("request_template_available")),
                        "request_template": assessment.get("request_template"),
                        "sql_error_markers": assessment.get("sql_error_markers") or [],
                    },
                }
            )
    return candidates


def _build_planner_hooks(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hooks: list[dict[str, Any]] = []
    seen: set[str] = set()
    for candidate in candidates:
        route_group = str(candidate.get("route_group") or "").strip()
        key = f"{route_group}:verify_suspected_injection"
        if not route_group or key in seen:
            continue
        seen.add(key)
        hooks.append(
            {
                "pack_key": "p3a_injection",
                "route_group": route_group,
                "planner_action": "verify_suspected_injection",
                "target_url": str(candidate.get("request_url") or candidate.get("url") or ""),
                "proof_contract": "injection_replay_contract",
                "attack_primitive": str(candidate.get("attack_primitive") or ""),
                "target_profile": str(candidate.get("target_profile") or ""),
            }
        )
    return hooks


def _route_assessment_counts(route_assessments: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "injection_candidate": 0,
        "graphql_candidate": 0,
        "heuristic_only": 0,
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
        "parameter_hypotheses": list(assessment.get("parameter_hypotheses") or []),
        "evidence_gaps": list(assessment.get("evidence_gaps") or []),
    }


def _evidence_gaps(
    *,
    assessment_state: str,
    replay_count: int,
    has_parameters: bool,
    graphql_surface: bool,
    graphql_template_available: bool,
    route_local_evidence: bool,
) -> list[str]:
    gaps: list[str] = []
    if assessment_state in {"injection_candidate", "graphql_candidate"}:
        gaps.append("verification")
    elif assessment_state == "heuristic_only":
        gaps.append("request_template")
    else:
        gaps.append("signal_strength")
    if replay_count == 0:
        gaps.append("replay_context")
    if not has_parameters:
        gaps.append("parameter_mapping")
    if graphql_surface and not graphql_template_available:
        gaps.append("request_body_shape")
    if not route_local_evidence:
        gaps.append("route_local_evidence")
    return _dedupe_strings(gaps)


def _assessment_reasoning(
    *,
    route_group: str,
    assessment_state: str,
    parameter_names: list[str],
    sql_error_markers: list[str],
    graphql_surface: bool,
    graphql_introspection_exposed: bool,
    evidence_gaps: list[str],
    negative_evidence: bool,
) -> str:
    if assessment_state == "graphql_candidate":
        if graphql_introspection_exposed:
            return (
                f"Route {route_group} exposes GraphQL introspection markers and has enough request context "
                "for bounded replay verification."
            )
        return (
            f"Route {route_group} looks like a GraphQL surface with structured input and should enter "
            "replayable query-shape verification."
        )
    if assessment_state == "injection_candidate":
        basis = "SQL error markers" if sql_error_markers else "parameter and replay context"
        return (
            f"Route {route_group} has {basis} and should enter parameter-differential replay verification."
        )
    if negative_evidence:
        return (
            f"Route {route_group} has heuristic injection pressure but no reliable replay context yet. "
            f"Remaining gaps: {', '.join(evidence_gaps[:3])}."
        )
    if graphql_surface and graphql_introspection_exposed:
        return f"Route {route_group} exposes GraphQL introspection markers but still lacks replayable request context."
    if graphql_surface:
        return f"Route {route_group} looks GraphQL-shaped but needs stronger request-body context."
    return f"Route {route_group} has weak injection signal and should be deprioritized."


def _build_ai_advisory_bundle(
    *,
    enabled: bool,
    target_profile: str,
    route_assessments: list[dict[str, Any]],
    route_assessment_counts: dict[str, int],
) -> dict[str, Any]:
    if not enabled:
        return {
            "enabled": False,
            "advisory_mode": "injection_parameter_focus",
            "prompt_contract": None,
            "focus_routes": [],
            "evidence_gap_summary": [],
            "user_prompt": "",
        }

    focus_routes = [
        {
            "route_group": str(item.get("route_group") or ""),
            "assessment_state": str(item.get("assessment_state") or ""),
            "risk_score": int(item.get("risk_score") or 0),
            "advisory_priority": int(item.get("advisory_priority") or 0),
            "parameter_hypotheses": list(item.get("parameter_hypotheses") or [])[:6],
            "query_shape_hints": list(item.get("query_shape_hints") or [])[:4],
            "candidate_vulnerability_types": list(item.get("candidate_vulnerability_types") or [])[:4],
            "evidence_gaps": list(item.get("evidence_gaps") or [])[:4],
            "request_template_available": bool(item.get("request_template_available")),
            "reasoning": str(item.get("reasoning") or ""),
        }
        for item in route_assessments[:5]
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
        "capability_pack": "p3a_injection",
        "advisory_mode": "injection_parameter_focus",
        "target_profile": target_profile,
        "route_assessment_counts": route_assessment_counts,
        "focus_routes": focus_routes,
        "evidence_gap_summary": evidence_gap_summary,
        "proof_contract_boundary": "advisor_only_no_truth_promotion",
    }
    prompt_contract = advisory_prompt_contract("injection_parameter_focus")
    user_prompt = build_json_user_prompt(
        prompt_contract,
        preamble=(
            "Review the injection route and parameter pressure below and recommend which routes, parameter sets, "
            "and request-shape gaps deserve the next bounded replay pass. Do not certify findings or proof. "
            "Optimize only for route ranking, parameter hypotheses, and evidence-gap closure."
        ),
        context=context,
    )
    return {
        "enabled": True,
        "advisory_mode": "injection_parameter_focus",
        "prompt_contract": {
            "contract_id": prompt_contract.contract_id,
            "prompt_version": prompt_contract.prompt_version,
            "task_type": prompt_contract.task_type,
            "response_format": prompt_contract.response_format,
        },
        "focus_routes": focus_routes,
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


def _query_parameter_names(url: str) -> list[str]:
    return _dedupe_strings([name for name, _value in parse_qsl(urlparse(url).query, keep_blank_values=True) if name])


def _query_shape_hints(parameter_names: list[str]) -> list[str]:
    hints = [
        name
        for name in parameter_names
        if any(token in str(name).lower() for token in (_JSON_QUERY_HINTS + _FORM_QUERY_HINTS))
    ]
    return _dedupe_strings(hints)


def _looks_like_graphql_endpoint(*, route_group: str, page_url: str) -> bool:
    lowered_route = str(route_group or "").lower()
    lowered_url = str(page_url or "").lower()
    return "/graphql" in lowered_route or "/graphql" in lowered_url


def _graphql_request_template(*, route_group: str) -> dict[str, Any]:
    operation_name = "PentraIntrospection"
    return {
        "method": "POST",
        "content_type": "application/json",
        "body": {
            "operationName": operation_name,
            "query": (
                "query PentraIntrospection { "
                "__schema { queryType { name } mutationType { name } } "
                "}"
            ),
            "variables": {},
        },
        "template_source": f"graphql_surface:{route_group}",
    }


def _sql_error_markers(text: str) -> list[str]:
    lowered = str(text or "").lower()
    return _dedupe_strings([marker for marker in _SQL_ERROR_MARKERS if marker in lowered])


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
