"""Parser, file, and upload abuse capability analysis and candidate generation."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

import yaml
from pentra_common.ai.prompt_contracts import advisory_prompt_contract, build_json_user_prompt

_CAPABILITY_DIR = Path(__file__).resolve().parent
_MANIFEST_PATH = _CAPABILITY_DIR / "capability_manifest.yaml"

_UPLOAD_ROUTE_HINTS = ("/upload", "/import", "/files", "/attachments", "/deserialize")
_UPLOAD_FIELD_HINTS = ("file", "document", "attachment", "upload", "filename", "contents")
_XML_FIELD_HINTS = ("xml", "doctype", "entity", "svg", "soap", "metadata")
_SERIALIZED_FIELD_HINTS = (
    "serialized",
    "serialize",
    "deserialize",
    "payload",
    "object",
    "pickle",
    "yaml",
    "stream",
)
_XML_RESPONSE_HINTS = (
    "xml parser",
    "doctype",
    "external entity",
    "entity handling",
    "xml import",
    "<invoice",
    "<?xml",
)
_SERIALIZATION_RESPONSE_HINTS = (
    "deserialization",
    "serialized object",
    "object graph",
    "objectinputstream",
    "pickle",
    "unsafe object",
)


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text()) or {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"Parser/file capability file must contain a YAML object: {path}")
    return payload


@lru_cache(maxsize=1)
def load_parser_file_abuse_capability_manifest() -> dict[str, Any]:
    return _load_yaml(_MANIFEST_PATH)


def build_parser_file_abuse_pack(
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
    del base_url, capability_results
    manifest = load_parser_file_abuse_capability_manifest()
    target_profile = _infer_target_profile(pages=pages, forms=forms, replays=replays)
    enabled = _pack_enabled(scan_config=scan_config, pages=pages, forms=forms, replays=replays)
    route_assessments = _build_route_assessments(
        pages=pages,
        forms=forms,
        sessions=sessions,
        replays=replays,
        probe_findings=probe_findings,
        target_profile=target_profile,
    )
    negative_evidence = [
        _negative_evidence_item(item)
        for item in route_assessments
        if bool(item.get("negative_evidence"))
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


def _pack_enabled(
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
        (
            f"{page.get('route_group') or ''} {page.get('url') or ''} {page.get('response_preview') or ''}".lower()
            for page in pages
            if isinstance(page, dict)
        )
    )
    if any(hint in route_text for hint in _UPLOAD_ROUTE_HINTS):
        return "upload_parser_heavy"
    if any(form.get("multipart") for form in forms if isinstance(form, dict)):
        return "upload_parser_heavy"
    if forms and not replays:
        return "traditional_server_rendered"
    return "spa_rest_api"


def _build_route_assessments(
    *,
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
                "file_field_names": set(),
                "form_methods": set(),
                "replay_count": 0,
                "upload_surface": False,
                "multipart_surface": False,
                "xml_surface": False,
                "serialized_surface": False,
                "route_local_evidence": False,
                "requires_auth": False,
                "probe_types": set(),
                "parser_error_markers": set(),
                "request_template": None,
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
        label = str(page.get("session_label") or "").strip()
        if label:
            item["session_labels"].add(label)
            item["auth_states"].add(session_states.get(label, str(page.get("auth_state") or "none")))
        if page.get("requires_auth"):
            item["requires_auth"] = True

        page_text = " ".join(
            [
                route_group.lower(),
                page_url.lower(),
                str(page.get("response_preview") or "").lower(),
                str(page.get("content_type") or "").lower(),
            ]
        )
        if any(hint in page_text for hint in _UPLOAD_ROUTE_HINTS):
            item["upload_surface"] = True
        if any(hint in page_text for hint in _XML_RESPONSE_HINTS):
            item["xml_surface"] = True
        if any(hint in page_text for hint in _SERIALIZATION_RESPONSE_HINTS):
            item["serialized_surface"] = True
        item["parser_error_markers"].update(_parser_error_markers(page_text))

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
        file_field_names = _string_list(form.get("file_field_names"))
        item["parameter_names"].update(field_names)
        item["file_field_names"].update(file_field_names)
        item["form_methods"].add(str(form.get("method") or "GET").strip().upper())
        if bool(form.get("multipart")):
            item["multipart_surface"] = True
            item["upload_surface"] = True
        form_text = " ".join(
            [
                route_group.lower(),
                page_url.lower(),
                action_url.lower(),
                " ".join(name.lower() for name in field_names),
                " ".join(name.lower() for name in file_field_names),
                str(form.get("enctype") or "").lower(),
            ]
        )
        if any(hint in form_text for hint in _UPLOAD_ROUTE_HINTS) or _matches_any(field_names + file_field_names, _UPLOAD_FIELD_HINTS):
            item["upload_surface"] = True
        if _matches_any(field_names, _XML_FIELD_HINTS):
            item["xml_surface"] = True
        if _matches_any(field_names, _SERIALIZED_FIELD_HINTS):
            item["serialized_surface"] = True
        label = str(form.get("session_label") or "").strip()
        if label:
            item["session_labels"].add(label)
            item["auth_states"].add(session_states.get(label, str(form.get("auth_state") or "none")))
        if form.get("requires_auth"):
            item["requires_auth"] = True
        if item["request_template"] is None:
            item["request_template"] = _request_template(
                action_url=action_url or page_url,
                method=str(form.get("method") or "GET").strip().upper(),
                parameter_names=field_names,
                file_field_names=file_field_names,
                multipart=bool(form.get("multipart")),
            )

    for replay in replays:
        target_url = str(replay.get("target_url") or "").strip()
        route_group = _route_group(target_url)
        if not route_group:
            continue
        item = ensure(route_group)
        item["replay_count"] += 1
        label = str(replay.get("session_label") or "").strip()
        if label:
            item["session_labels"].add(label)
            item["auth_states"].add(session_states.get(label, "none"))
        replay_text = target_url.lower()
        if any(hint in replay_text for hint in _UPLOAD_ROUTE_HINTS):
            item["upload_surface"] = True
        if any(hint in replay_text for hint in _XML_FIELD_HINTS):
            item["xml_surface"] = True
        if any(hint in replay_text for hint in _SERIALIZED_FIELD_HINTS):
            item["serialized_surface"] = True
        if item["request_template"] is None:
            item["request_template"] = _request_template(
                action_url=target_url,
                method="POST" if any(item["form_methods"]) else "GET",
                parameter_names=_query_parameter_names(target_url),
                file_field_names=[],
                multipart=bool(item["multipart_surface"]),
            )

    for finding in probe_findings:
        route_group = str(
            finding.get("route_group")
            or _route_group(str(finding.get("endpoint") or finding.get("target") or ""))
        ).strip()
        if not route_group:
            continue
        item = ensure(route_group)
        vuln_type = str(finding.get("vulnerability_type") or "").strip().lower()
        if vuln_type:
            item["probe_types"].add(vuln_type)
        text = " ".join(
            part
            for part in (
                str(finding.get("description") or ""),
                str(finding.get("response") or ""),
                str(finding.get("exploit_result") or ""),
            )
            if part
        ).lower()
        if "xxe" in vuln_type or any(hint in text for hint in _XML_RESPONSE_HINTS):
            item["xml_surface"] = True
        if "deserialization" in vuln_type or any(hint in text for hint in _SERIALIZATION_RESPONSE_HINTS):
            item["serialized_surface"] = True
        item["parser_error_markers"].update(_parser_error_markers(text))

    assessments: list[dict[str, Any]] = []
    for route_group, item in grouped.items():
        parameter_names = _dedupe_strings(sorted(item["parameter_names"]))
        file_field_names = _dedupe_strings(sorted(item["file_field_names"]))
        session_labels = _dedupe_strings(sorted(item["session_labels"]))
        auth_states = _dedupe_strings(sorted(item["auth_states"]))
        parser_error_markers = _dedupe_strings(sorted(item["parser_error_markers"]))
        probe_types = _dedupe_strings(sorted(item["probe_types"]))
        request_template = item["request_template"] if isinstance(item["request_template"], dict) else None
        request_template_available = bool(request_template) or item["replay_count"] > 0

        assessment_state = "low_signal"
        attack_primitive = ""
        proof_contracts: list[str] = []
        candidate_vulnerability_types: list[str] = []
        risk_score = 12
        negative_evidence = False

        if bool(item["xml_surface"]) and request_template_available:
            assessment_state = "xxe_candidate"
            attack_primitive = "xxe_parser_endpoint_probe"
            proof_contracts = ["xxe_parser_contract"]
            candidate_vulnerability_types = ["xxe"]
            risk_score = 74
        elif bool(item["serialized_surface"]) and request_template_available:
            assessment_state = "deserialization_candidate"
            attack_primitive = "deserialization_replay_probe"
            proof_contracts = ["deserialization_replay_contract"]
            candidate_vulnerability_types = ["insecure_deserialization"]
            risk_score = 71
        elif bool(item["upload_surface"] or item["multipart_surface"] or item["xml_surface"] or item["serialized_surface"]):
            assessment_state = "heuristic_only"
            attack_primitive = (
                "xxe_parser_endpoint_probe"
                if item["xml_surface"]
                else "deserialization_replay_probe"
                if item["serialized_surface"]
                else "xxe_parser_endpoint_probe"
            )
            proof_contracts = (
                ["xxe_parser_contract"]
                if item["xml_surface"]
                else ["deserialization_replay_contract"]
                if item["serialized_surface"]
                else []
            )
            candidate_vulnerability_types = (
                ["xxe"]
                if item["xml_surface"]
                else ["insecure_deserialization"]
                if item["serialized_surface"]
                else []
            )
            risk_score = 34
            negative_evidence = not request_template_available

        risk_score += min(len(parameter_names), 4) * 4
        risk_score += min(len(file_field_names), 2) * 5
        risk_score += min(item["replay_count"], 2) * 5
        risk_score += min(len(parser_error_markers), 2) * 7
        if item["upload_surface"]:
            risk_score += 8
        if item["multipart_surface"]:
            risk_score += 6
        if target_profile == "upload_parser_heavy" and (item["upload_surface"] or item["xml_surface"] or item["serialized_surface"]):
            risk_score += 8

        evidence_gaps = _evidence_gaps(
            assessment_state=assessment_state,
            request_template_available=request_template_available,
            has_parameters=bool(parameter_names or file_field_names),
            xml_surface=bool(item["xml_surface"]),
            serialized_surface=bool(item["serialized_surface"]),
            route_local_evidence=bool(item["route_local_evidence"]),
        )
        reasoning = _assessment_reasoning(
            route_group=route_group,
            assessment_state=assessment_state,
            upload_surface=bool(item["upload_surface"]),
            multipart_surface=bool(item["multipart_surface"]),
            xml_surface=bool(item["xml_surface"]),
            serialized_surface=bool(item["serialized_surface"]),
            evidence_gaps=evidence_gaps,
            negative_evidence=negative_evidence,
        )

        assessments.append(
            {
                "route_group": route_group,
                "page_url": sorted(item["page_urls"])[0] if item["page_urls"] else "",
                "assessment_state": assessment_state,
                "risk_score": min(risk_score, 100),
                "advisory_priority": min(
                    risk_score + (10 if assessment_state in {"xxe_candidate", "deserialization_candidate"} else 0),
                    100,
                ),
                "candidate_count": 1 if assessment_state in {"xxe_candidate", "deserialization_candidate"} else 0,
                "parameter_hypotheses": parameter_names[:8],
                "file_field_names": file_field_names[:6],
                "proof_contracts": proof_contracts,
                "planner_action": "probe_parser_boundaries",
                "attack_primitive": attack_primitive,
                "session_labels": session_labels,
                "auth_states": auth_states,
                "requires_auth": bool(item["requires_auth"]),
                "upload_surface": bool(item["upload_surface"]),
                "multipart_surface": bool(item["multipart_surface"]),
                "xml_surface": bool(item["xml_surface"]),
                "serialized_surface": bool(item["serialized_surface"]),
                "request_template_available": request_template_available,
                "request_template": request_template,
                "parser_error_markers": parser_error_markers,
                "replay_count": int(item["replay_count"]),
                "negative_evidence": negative_evidence,
                "candidate_vulnerability_types": candidate_vulnerability_types,
                "probe_types": probe_types,
                "evidence_gaps": evidence_gaps,
                "next_action": "probe_parser_boundaries",
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
        if state not in {"xxe_candidate", "deserialization_candidate"}:
            continue
        route_group = str(assessment.get("route_group") or "")
        page_url = str(assessment.get("page_url") or "")
        proof_contract = _string_list(assessment.get("proof_contracts"))[0]
        attack_primitive = str(assessment.get("attack_primitive") or "")
        for vulnerability_type in _string_list(assessment.get("candidate_vulnerability_types")):
            candidates.append(
                {
                    "candidate_key": f"{route_group}:{state}:{vulnerability_type}",
                    "request_url": page_url,
                    "url": page_url,
                    "target": page_url,
                    "endpoint": page_url,
                    "title": "Parser/file capability candidate",
                    "severity": "medium",
                    "confidence": int(assessment.get("risk_score") or 0),
                    "description": str(assessment.get("reasoning") or ""),
                    "tool_source": "web_interact",
                    "vulnerability_type": vulnerability_type,
                    "surface": "web",
                    "route_group": route_group,
                    "verification_state": "suspected",
                    "verification_confidence": int(assessment.get("risk_score") or 0),
                    "references": [
                        *[f"param:{name}" for name in assessment.get("parameter_hypotheses") or []][:5],
                        *[f"file:{name}" for name in assessment.get("file_field_names") or []][:3],
                        *[f"signal:{name}" for name in assessment.get("parser_error_markers") or []][:3],
                    ],
                    "challenge_family": "xxe" if vulnerability_type == "xxe" else "insecure_deserialization",
                    "attack_primitive": attack_primitive,
                    "workflow_state": "authenticated_surface" if bool(assessment.get("requires_auth")) else "anonymous_surface",
                    "workflow_stage": "analysis",
                    "planner_action": "probe_parser_boundaries",
                    "proof_contract": proof_contract,
                    "target_profile": target_profile,
                    "capability_pack": "p3a_parser_file_abuse",
                    "triggering_condition": state,
                    "route_context": {
                        "session_labels": assessment.get("session_labels") or [],
                        "auth_states": assessment.get("auth_states") or [],
                        "upload_surface": bool(assessment.get("upload_surface")),
                        "multipart_surface": bool(assessment.get("multipart_surface")),
                        "xml_surface": bool(assessment.get("xml_surface")),
                        "serialized_surface": bool(assessment.get("serialized_surface")),
                        "replay_count": int(assessment.get("replay_count") or 0),
                    },
                    "verification_context": {
                        "verify_type": "parser_boundary_replay",
                        "route_group": route_group,
                        "page_url": page_url,
                        "attack_primitive": attack_primitive,
                        "parameter_hypotheses": assessment.get("parameter_hypotheses") or [],
                        "file_field_names": assessment.get("file_field_names") or [],
                        "upload_surface": bool(assessment.get("upload_surface")),
                        "xml_surface": bool(assessment.get("xml_surface")),
                        "serialized_surface": bool(assessment.get("serialized_surface")),
                        "request_template_available": bool(assessment.get("request_template_available")),
                        "request_template": assessment.get("request_template"),
                        "parser_error_markers": assessment.get("parser_error_markers") or [],
                    },
                }
            )
    return candidates


def _build_planner_hooks(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hooks: list[dict[str, Any]] = []
    seen: set[str] = set()
    for candidate in candidates:
        route_group = str(candidate.get("route_group") or "").strip()
        key = f"{route_group}:probe_parser_boundaries"
        if not route_group or key in seen:
            continue
        seen.add(key)
        hooks.append(
            {
                "pack_key": "p3a_parser_file_abuse",
                "route_group": route_group,
                "planner_action": "probe_parser_boundaries",
                "target_url": str(candidate.get("request_url") or candidate.get("url") or ""),
                "proof_contract": str(candidate.get("proof_contract") or ""),
                "attack_primitive": str(candidate.get("attack_primitive") or ""),
                "target_profile": str(candidate.get("target_profile") or ""),
            }
        )
    return hooks


def _route_assessment_counts(route_assessments: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "xxe_candidate": 0,
        "deserialization_candidate": 0,
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
        "file_field_names": list(assessment.get("file_field_names") or []),
        "evidence_gaps": list(assessment.get("evidence_gaps") or []),
    }


def _evidence_gaps(
    *,
    assessment_state: str,
    request_template_available: bool,
    has_parameters: bool,
    xml_surface: bool,
    serialized_surface: bool,
    route_local_evidence: bool,
) -> list[str]:
    gaps: list[str] = []
    if assessment_state in {"xxe_candidate", "deserialization_candidate"}:
        gaps.append("verification")
    elif assessment_state == "heuristic_only":
        gaps.append("request_template")
    else:
        gaps.append("signal_strength")
    if not request_template_available:
        gaps.append("replay_context")
    if not has_parameters:
        gaps.append("parser_input")
    if xml_surface:
        gaps.append("parser_response_delta")
    if serialized_surface:
        gaps.append("object_behavior_delta")
    if not route_local_evidence:
        gaps.append("route_local_evidence")
    return _dedupe_strings(gaps)


def _assessment_reasoning(
    *,
    route_group: str,
    assessment_state: str,
    upload_surface: bool,
    multipart_surface: bool,
    xml_surface: bool,
    serialized_surface: bool,
    evidence_gaps: list[str],
    negative_evidence: bool,
) -> str:
    if assessment_state == "xxe_candidate":
        return (
            f"Route {route_group} exposes replayable XML parser pressure and should enter bounded XXE parser verification."
        )
    if assessment_state == "deserialization_candidate":
        return (
            f"Route {route_group} exposes replayable serialized-input pressure and should enter bounded deserialization verification."
        )
    if negative_evidence:
        return (
            f"Route {route_group} has upload or parser pressure but lacks enough replay context. "
            f"Remaining gaps: {', '.join(evidence_gaps[:3])}."
        )
    if upload_surface and multipart_surface:
        return f"Route {route_group} looks like a multipart upload surface but needs stronger parser-specific replay context."
    if xml_surface:
        return f"Route {route_group} looks XML-capable but needs stronger parser-response evidence."
    if serialized_surface:
        return f"Route {route_group} looks serialization-capable but needs stronger object-behavior evidence."
    return f"Route {route_group} has weak parser/upload signal and should be deprioritized."


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
            "advisory_mode": "parser_boundary_focus",
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
            "file_field_names": list(item.get("file_field_names") or [])[:4],
            "candidate_vulnerability_types": list(item.get("candidate_vulnerability_types") or [])[:4],
            "evidence_gaps": list(item.get("evidence_gaps") or [])[:4],
            "upload_surface": bool(item.get("upload_surface")),
            "xml_surface": bool(item.get("xml_surface")),
            "serialized_surface": bool(item.get("serialized_surface")),
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
        "capability_pack": "p3a_parser_file_abuse",
        "advisory_mode": "parser_boundary_focus",
        "target_profile": target_profile,
        "route_assessment_counts": route_assessment_counts,
        "focus_routes": focus_routes,
        "evidence_gap_summary": evidence_gap_summary,
        "proof_contract_boundary": "advisor_only_no_truth_promotion",
    }
    prompt_contract = advisory_prompt_contract("parser_boundary_focus")
    user_prompt = build_json_user_prompt(
        prompt_contract,
        preamble=(
            "Review the parser, upload, XML, and serialization pressure below and recommend which routes, "
            "request shapes, and evidence gaps deserve the next bounded parser-boundary replay pass. "
            "Do not certify findings or proof. Optimize only for route ranking, request-shape hypotheses, "
            "and evidence-gap closure."
        ),
        context=context,
    )
    return {
        "enabled": True,
        "advisory_mode": "parser_boundary_focus",
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
    return path.rstrip("/") or "/"


def _query_parameter_names(url: str) -> list[str]:
    return [name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True) if name]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _dedupe_strings(items: list[str]) -> list[str]:
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


def _matches_any(items: list[str], hints: tuple[str, ...]) -> bool:
    lowered = " ".join(str(item).strip().lower() for item in items if str(item).strip())
    return any(hint in lowered for hint in hints)


def _parser_error_markers(text: str) -> list[str]:
    markers: list[str] = []
    lowered = text.lower()
    for marker in (*_XML_RESPONSE_HINTS, *_SERIALIZATION_RESPONSE_HINTS):
        if marker in lowered:
            markers.append(marker)
    return _dedupe_strings(markers)


def _request_template(
    *,
    action_url: str,
    method: str,
    parameter_names: list[str],
    file_field_names: list[str],
    multipart: bool,
) -> dict[str, Any]:
    return {
        "method": method,
        "url": action_url,
        "parameter_names": _dedupe_strings(parameter_names)[:8],
        "file_field_names": _dedupe_strings(file_field_names)[:4],
        "content_type": "multipart/form-data" if multipart else "application/x-www-form-urlencoded",
    }
