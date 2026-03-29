"""Disclosure, misconfiguration, crypto, and component capability analysis."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

import yaml
from pentra_common.ai.prompt_contracts import advisory_prompt_contract, build_json_user_prompt

_CAPABILITY_DIR = Path(__file__).resolve().parent
_MANIFEST_PATH = _CAPABILITY_DIR / "capability_manifest.yaml"

_ADMIN_ROUTE_HINTS = ("/admin", "/manage", "/settings", "/internal", "/debug", "/users")
_UPLOAD_ROUTE_HINTS = ("/upload", "/import", "/attachments", "/files")
_API_ROUTE_HINTS = ("/api/", "/graphql", "/openapi", "/swagger")
_COMPONENT_ROUTE_HINTS = (
    "/openapi",
    "/swagger",
    "/api-docs",
    "/graphql",
    "/robots.txt",
    "/security.txt",
    "/.well-known/",
)
_COMPONENT_MARKER_PATTERNS = (
    "openapi",
    "swagger",
    "graphql",
    "security.txt",
    "robots.txt",
    "version",
)
_STACK_TRACE_MARKERS = (
    "stacktrace",
    "traceback",
    "exception:",
    "exception ",
    "internal server error",
    "uid=",
    "debug=true",
)
_CONFIG_MARKERS = (
    "\"config\"",
    "\"debug\"",
    "debug=true",
    "application-configuration",
    "\"env\"",
    "\"environment\"",
    "\"showversionnumber\"",
    "\"localbackupenabled\"",
)
_SECRET_MARKERS = (
    "jwt_secret",
    "client_secret",
    "secret_key",
    "api_key",
    "access_key",
    "private_key",
    "\"token\"",
    "authorization: bearer",
)
_CRYPTO_MARKERS = (
    "hs256",
    "sha1",
    "md5",
    "des",
    "rc4",
    "-----begin private key-----",
    "-----begin certificate-----",
    "jwt_secret",
    "public key",
)
_PUBLIC_ASSET_MARKERS = (
    "\"openapi\"",
    "\"paths\"",
    "swagger ui",
    "user-agent:",
    "contact:",
    "expires:",
)


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text()) or {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"Disclosure capability file must contain a YAML object: {path}")
    return payload


@lru_cache(maxsize=1)
def load_disclosure_misconfig_crypto_capability_manifest() -> dict[str, Any]:
    return _load_yaml(_MANIFEST_PATH)


def build_disclosure_misconfig_crypto_pack(
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
    manifest = load_disclosure_misconfig_crypto_capability_manifest()
    target_profile = _infer_target_profile(pages=pages, forms=forms, replays=replays)
    enabled = _pack_enabled(scan_config=scan_config, pages=pages, replays=replays, probe_findings=probe_findings)
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
    replays: list[dict[str, Any]],
    probe_findings: list[dict[str, Any]],
) -> bool:
    stateful = scan_config.get("stateful_testing", {})
    if isinstance(stateful, dict) and "enabled" in stateful and not bool(stateful.get("enabled")):
        return False
    return bool(pages or replays or probe_findings)


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
    if any(hint in route_text for hint in _ADMIN_ROUTE_HINTS):
        return "auth_heavy_admin_portal"
    if replays or any(hint in route_text for hint in _API_ROUTE_HINTS):
        return "spa_rest_api"
    if forms:
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
                "probe_types": set(),
                "status_codes": set(),
                "replay_count": 0,
                "route_local_evidence": False,
                "requires_auth": False,
                "public_surface": False,
                "debug_surface": False,
                "config_surface": False,
                "component_surface": False,
                "secret_surface": False,
                "crypto_surface": False,
                "openapi_exposed": False,
                "stack_trace_markers": set(),
                "component_markers": set(),
                "config_markers": set(),
                "secret_markers": set(),
                "crypto_markers": set(),
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
        status_code = int(page.get("status_code") or 0)
        if status_code:
            item["status_codes"].add(status_code)
        label = str(page.get("session_label") or "").strip()
        if label:
            item["session_labels"].add(label)
            item["auth_states"].add(session_states.get(label, str(page.get("auth_state") or "none")))
        auth_state = str(page.get("auth_state") or "").strip().lower()
        if auth_state in {"", "none", "anonymous"}:
            item["public_surface"] = True
        if page.get("requires_auth"):
            item["requires_auth"] = True

        page_text = " ".join(
            [
                route_group.lower(),
                page_url.lower(),
                str(page.get("title") or "").lower(),
                str(page.get("response_preview") or "").lower(),
                str(page.get("content_type") or "").lower(),
                str(page.get("vulnerability_type") or "").lower(),
            ]
        )
        item["component_markers"].update(_component_markers(page_url, page_text))
        item["stack_trace_markers"].update(_match_markers(page_text, _STACK_TRACE_MARKERS))
        item["config_markers"].update(_match_markers(page_text, _CONFIG_MARKERS))
        item["secret_markers"].update(_match_markers(page_text, _SECRET_MARKERS))
        item["crypto_markers"].update(_match_markers(page_text, _CRYPTO_MARKERS))

        if _looks_like_component_surface(page_url, page_text):
            item["component_surface"] = True
        if _looks_like_openapi(page_url, page_text):
            item["component_surface"] = True
            item["openapi_exposed"] = True
        if _looks_like_debug_surface(page_url, page_text, status_code=status_code):
            item["debug_surface"] = True
        if item["config_markers"]:
            item["config_surface"] = True
        if item["secret_markers"]:
            item["secret_surface"] = True
        if item["crypto_markers"]:
            item["crypto_surface"] = True

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
        item["parameter_names"].update(_string_list(form.get("field_names")))
        label = str(form.get("session_label") or "").strip()
        if label:
            item["session_labels"].add(label)
            item["auth_states"].add(session_states.get(label, str(form.get("auth_state") or "none")))
        auth_state = str(form.get("auth_state") or "").strip().lower()
        if auth_state in {"", "none", "anonymous"}:
            item["public_surface"] = True
        if form.get("requires_auth"):
            item["requires_auth"] = True

    for replay in replays:
        target_url = str(replay.get("target_url") or "").strip()
        route_group = _route_group(target_url)
        if not route_group:
            continue
        item = ensure(route_group)
        item["replay_count"] += 1
        if target_url:
            item["page_urls"].add(target_url)
        label = str(replay.get("session_label") or "").strip()
        if label:
            item["session_labels"].add(label)
            item["auth_states"].add(session_states.get(label, "none"))
        replay_text = " ".join(
            [
                route_group.lower(),
                target_url.lower(),
                str(replay.get("response_preview") or "").lower(),
            ]
        )
        item["component_markers"].update(_component_markers(target_url, replay_text))
        item["stack_trace_markers"].update(_match_markers(replay_text, _STACK_TRACE_MARKERS))
        item["config_markers"].update(_match_markers(replay_text, _CONFIG_MARKERS))
        item["secret_markers"].update(_match_markers(replay_text, _SECRET_MARKERS))
        item["crypto_markers"].update(_match_markers(replay_text, _CRYPTO_MARKERS))
        if _looks_like_openapi(target_url, replay_text):
            item["component_surface"] = True
            item["openapi_exposed"] = True
        if item["config_markers"]:
            item["config_surface"] = True
        if item["secret_markers"]:
            item["secret_surface"] = True
        if item["crypto_markers"]:
            item["crypto_surface"] = True

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
            [
                route_group.lower(),
                str(finding.get("title") or "").lower(),
                str(finding.get("description") or "").lower(),
                str(finding.get("response") or "").lower(),
                str(finding.get("exploit_result") or "").lower(),
            ]
        )
        item["component_markers"].update(_component_markers(route_group, text))
        item["stack_trace_markers"].update(_match_markers(text, _STACK_TRACE_MARKERS))
        item["config_markers"].update(_match_markers(text, _CONFIG_MARKERS))
        item["secret_markers"].update(_match_markers(text, _SECRET_MARKERS))
        item["crypto_markers"].update(_match_markers(text, _CRYPTO_MARKERS))

        if vuln_type in {"stack_trace_exposure", "debug_exposure"}:
            item["debug_surface"] = True
        if vuln_type in {"sensitive_data_exposure", "credential_exposure", "sensitive_config_exposure"}:
            item["config_surface"] = True
            item["secret_surface"] = True
        if vuln_type == "openapi_exposure":
            item["component_surface"] = True
            item["openapi_exposed"] = True
        if vuln_type == "cors_misconfiguration":
            item["config_surface"] = True

    assessments: list[dict[str, Any]] = []
    for route_group, item in grouped.items():
        session_labels = _dedupe_strings(sorted(item["session_labels"]))
        auth_states = _dedupe_strings(sorted(item["auth_states"]))
        parameter_names = _dedupe_strings(sorted(item["parameter_names"]))
        probe_types = _dedupe_strings(sorted(item["probe_types"]))
        stack_trace_markers = _dedupe_strings(sorted(item["stack_trace_markers"]))
        component_markers = _dedupe_strings(sorted(item["component_markers"]))
        config_markers = _dedupe_strings(sorted(item["config_markers"]))
        secret_markers = _dedupe_strings(sorted(item["secret_markers"]))
        crypto_markers = _dedupe_strings(sorted(item["crypto_markers"]))
        page_urls = _dedupe_strings(sorted(item["page_urls"]))
        status_codes = sorted(int(code) for code in item["status_codes"] if int(code) > 0)

        if any(state in {"none", "anonymous"} for state in auth_states) or not auth_states:
            item["public_surface"] = True
        requires_auth = bool(item["requires_auth"]) and not item["public_surface"]

        assessment_state = "low_signal"
        attack_primitive = "misconfiguration_surface_probe"
        planner_action = "inspect_config_and_secret_exposure"
        proof_contracts: list[str] = []
        candidate_vulnerability_types: list[str] = []
        negative_evidence = False
        risk_score = 14

        has_route_truth = bool(page_urls or probe_types)
        if stack_trace_markers and (500 in status_codes or "stack_trace_exposure" in probe_types or "debug_exposure" in probe_types):
            assessment_state = "stack_trace_candidate"
            attack_primitive = "stack_trace_and_log_disclosure_probe"
            planner_action = "inspect_error_and_log_disclosure"
            proof_contracts = ["stack_trace_disclosure_contract"]
            candidate_vulnerability_types = ["stack_trace_exposure"]
            risk_score = 84
        elif item["openapi_exposed"]:
            assessment_state = "component_truth_candidate"
            attack_primitive = "component_and_asset_fingerprint_probe"
            planner_action = "fingerprint_components_and_hidden_assets"
            proof_contracts = ["component_truth_contract"]
            candidate_vulnerability_types = ["openapi_exposure"]
            risk_score = 73
        elif (item["config_surface"] or "sensitive_data_exposure" in probe_types or "credential_exposure" in probe_types) and (
            item["secret_surface"] or "credential_exposure" in probe_types
        ) and has_route_truth:
            if item["crypto_surface"] or crypto_markers:
                assessment_state = "weak_crypto_candidate"
                attack_primitive = "weak_crypto_material_inspection"
                planner_action = "inspect_config_and_secret_exposure"
                proof_contracts = ["weak_crypto_material_contract", "misconfiguration_surface_contract"]
                candidate_vulnerability_types = ["credential_exposure"]
                risk_score = 82
            else:
                assessment_state = "disclosure_candidate"
                attack_primitive = "misconfiguration_surface_probe"
                planner_action = "inspect_config_and_secret_exposure"
                proof_contracts = ["sensitive_data_exposure_replay", "misconfiguration_surface_contract"]
                candidate_vulnerability_types = ["credential_exposure"]
                risk_score = 78
        elif (item["config_surface"] or item["debug_surface"] or "cors_misconfiguration" in probe_types) and has_route_truth:
            assessment_state = "misconfiguration_candidate"
            attack_primitive = "misconfiguration_surface_probe"
            planner_action = "inspect_config_and_secret_exposure"
            proof_contracts = ["misconfiguration_surface_contract"]
            candidate_vulnerability_types = (
                ["debug_exposure"]
                if item["debug_surface"] and not stack_trace_markers
                else ["cors_misconfiguration"] if "cors_misconfiguration" in probe_types else ["sensitive_data_exposure"]
            )
            risk_score = 62
        elif item["component_surface"] or item["config_surface"] or item["debug_surface"] or item["secret_surface"] or item["crypto_surface"]:
            assessment_state = "heuristic_only"
            attack_primitive = (
                "component_and_asset_fingerprint_probe"
                if item["component_surface"]
                else "weak_crypto_material_inspection"
                if item["crypto_surface"]
                else "misconfiguration_surface_probe"
            )
            candidate_vulnerability_types = (
                ["openapi_exposure"]
                if item["component_surface"]
                else ["credential_exposure"]
                if item["secret_surface"] or item["crypto_surface"]
                else ["stack_trace_exposure"]
                if item["debug_surface"]
                else ["sensitive_data_exposure"]
            )
            risk_score = 30
            negative_evidence = not has_route_truth

        risk_score += min(len(parameter_names), 3) * 3
        risk_score += min(len(component_markers), 3) * 5
        risk_score += min(len(config_markers), 3) * 4
        risk_score += min(len(secret_markers), 2) * 6
        risk_score += min(len(crypto_markers), 2) * 6
        risk_score += min(len(stack_trace_markers), 2) * 7
        risk_score += min(item["replay_count"], 2) * 4
        if item["public_surface"]:
            risk_score += 6
        if item["openapi_exposed"]:
            risk_score += 10
        if target_profile == "auth_heavy_admin_portal" and requires_auth:
            risk_score += 5
        risk_score = max(min(risk_score, 100), 0)
        advisory_priority = max(
            min(
                risk_score
                + (12 if assessment_state.endswith("_candidate") else 0)
                + (4 if item["public_surface"] else 0)
                - (6 if negative_evidence else 0),
                100,
            ),
            0,
        )
        evidence_gaps = _evidence_gaps(
            assessment_state=assessment_state,
            route_local_evidence=bool(item["route_local_evidence"]),
            has_route_truth=has_route_truth,
            requires_auth=requires_auth,
            public_surface=bool(item["public_surface"]),
            has_disclosed_markers=bool(config_markers or secret_markers or crypto_markers or stack_trace_markers),
            openapi_exposed=bool(item["openapi_exposed"]),
        )
        reasoning = _assessment_reasoning(
            route_group=route_group,
            assessment_state=assessment_state,
            public_surface=bool(item["public_surface"]),
            evidence_gaps=evidence_gaps,
            stack_trace_markers=stack_trace_markers,
            component_markers=component_markers,
            config_markers=config_markers,
            secret_markers=secret_markers,
            crypto_markers=crypto_markers,
            negative_evidence=negative_evidence,
        )

        assessments.append(
            {
                "route_group": route_group,
                "page_url": page_urls[0] if page_urls else "",
                "page_urls": page_urls,
                "assessment_state": assessment_state,
                "risk_score": risk_score,
                "advisory_priority": advisory_priority,
                "reasoning": reasoning,
                "parameter_hypotheses": parameter_names,
                "candidate_vulnerability_types": candidate_vulnerability_types,
                "proof_contracts": proof_contracts,
                "attack_primitive": attack_primitive,
                "planner_action": planner_action,
                "session_labels": session_labels,
                "auth_states": auth_states,
                "requires_auth": requires_auth,
                "public_surface": bool(item["public_surface"]),
                "debug_surface": bool(item["debug_surface"]),
                "config_surface": bool(item["config_surface"]),
                "component_surface": bool(item["component_surface"]),
                "secret_surface": bool(item["secret_surface"]),
                "crypto_surface": bool(item["crypto_surface"]),
                "openapi_exposed": bool(item["openapi_exposed"]),
                "stack_trace_markers": stack_trace_markers,
                "component_markers": component_markers,
                "config_markers": config_markers,
                "secret_markers": secret_markers,
                "crypto_markers": crypto_markers,
                "probe_types": probe_types,
                "replay_count": int(item["replay_count"]),
                "status_codes": status_codes,
                "route_local_evidence": bool(item["route_local_evidence"]),
                "negative_evidence": negative_evidence,
                "evidence_gaps": evidence_gaps,
            }
        )

    return sorted(
        assessments,
        key=lambda item: (
            -int(item.get("advisory_priority") or 0),
            -int(item.get("risk_score") or 0),
            str(item.get("route_group") or ""),
        ),
    )


def _build_candidates(
    *,
    route_assessments: list[dict[str, Any]],
    target_profile: str,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for assessment in route_assessments:
        state = str(assessment.get("assessment_state") or "")
        if state not in {
            "disclosure_candidate",
            "stack_trace_candidate",
            "component_truth_candidate",
            "misconfiguration_candidate",
            "weak_crypto_candidate",
        }:
            continue
        route_group = str(assessment.get("route_group") or "")
        page_url = str(assessment.get("page_url") or "")
        proof_contract = _string_list(assessment.get("proof_contracts"))[0]
        attack_primitive = str(assessment.get("attack_primitive") or "")
        planner_action = str(assessment.get("planner_action") or "")
        severity = "high" if state in {"disclosure_candidate", "stack_trace_candidate", "weak_crypto_candidate"} else "medium"
        for vulnerability_type in _string_list(assessment.get("candidate_vulnerability_types")):
            references = [
                *[f"marker:{name}" for name in assessment.get("stack_trace_markers") or []][:3],
                *[f"component:{name}" for name in assessment.get("component_markers") or []][:3],
                *[f"config:{name}" for name in assessment.get("config_markers") or []][:3],
                *[f"secret:{name}" for name in assessment.get("secret_markers") or []][:3],
                *[f"crypto:{name}" for name in assessment.get("crypto_markers") or []][:3],
            ]
            candidates.append(
                {
                    "candidate_key": f"{route_group}:{state}:{vulnerability_type}",
                    "request_url": page_url,
                    "url": page_url,
                    "target": page_url,
                    "endpoint": page_url,
                    "title": "Disclosure/misconfiguration capability candidate",
                    "severity": severity,
                    "confidence": int(assessment.get("risk_score") or 0),
                    "description": str(assessment.get("reasoning") or ""),
                    "tool_source": "web_interact",
                    "vulnerability_type": vulnerability_type,
                    "surface": "api" if "/api/" in route_group or "/graphql" in route_group else "web",
                    "route_group": route_group,
                    "verification_state": "suspected",
                    "verification_confidence": int(assessment.get("risk_score") or 0),
                    "references": references[:8],
                    "challenge_family": _challenge_family_for_state(state, vulnerability_type),
                    "attack_primitive": attack_primitive,
                    "workflow_state": "authenticated_surface" if bool(assessment.get("requires_auth")) else "anonymous_surface",
                    "workflow_stage": "analysis",
                    "planner_action": planner_action,
                    "proof_contract": proof_contract,
                    "target_profile": target_profile,
                    "capability_pack": "p3a_disclosure_misconfig_crypto",
                    "triggering_condition": state,
                    "route_context": {
                        "session_labels": assessment.get("session_labels") or [],
                        "auth_states": assessment.get("auth_states") or [],
                        "public_surface": bool(assessment.get("public_surface")),
                        "debug_surface": bool(assessment.get("debug_surface")),
                        "config_surface": bool(assessment.get("config_surface")),
                        "component_surface": bool(assessment.get("component_surface")),
                        "secret_surface": bool(assessment.get("secret_surface")),
                        "crypto_surface": bool(assessment.get("crypto_surface")),
                        "replay_count": int(assessment.get("replay_count") or 0),
                    },
                    "verification_context": {
                        "verify_type": "response_truth_replay",
                        "route_group": route_group,
                        "page_url": page_url,
                        "attack_primitive": attack_primitive,
                        "parameter_hypotheses": assessment.get("parameter_hypotheses") or [],
                        "stack_trace_markers": assessment.get("stack_trace_markers") or [],
                        "component_markers": assessment.get("component_markers") or [],
                        "config_markers": assessment.get("config_markers") or [],
                        "secret_markers": assessment.get("secret_markers") or [],
                        "crypto_markers": assessment.get("crypto_markers") or [],
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
                "pack_key": "p3a_disclosure_misconfig_crypto",
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
        "disclosure_candidate": 0,
        "stack_trace_candidate": 0,
        "component_truth_candidate": 0,
        "misconfiguration_candidate": 0,
        "weak_crypto_candidate": 0,
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
        "candidate_vulnerability_types": list(assessment.get("candidate_vulnerability_types") or []),
        "evidence_gaps": list(assessment.get("evidence_gaps") or []),
    }


def _evidence_gaps(
    *,
    assessment_state: str,
    route_local_evidence: bool,
    has_route_truth: bool,
    requires_auth: bool,
    public_surface: bool,
    has_disclosed_markers: bool,
    openapi_exposed: bool,
) -> list[str]:
    gaps: list[str] = []
    if assessment_state.endswith("_candidate"):
        gaps.append("verification")
    elif assessment_state == "heuristic_only":
        gaps.append("signal_strength")
    else:
        gaps.append("triage")
    if not has_route_truth:
        gaps.append("response_artifact")
    if not route_local_evidence:
        gaps.append("route_local_evidence")
    if requires_auth and not public_surface:
        gaps.append("auth_context")
    if assessment_state in {"disclosure_candidate", "weak_crypto_candidate", "misconfiguration_candidate"} and not has_disclosed_markers:
        gaps.append("exact_disclosed_fields")
    if assessment_state == "component_truth_candidate" and not openapi_exposed:
        gaps.append("asset_truth")
    return _dedupe_strings(gaps)


def _assessment_reasoning(
    *,
    route_group: str,
    assessment_state: str,
    public_surface: bool,
    evidence_gaps: list[str],
    stack_trace_markers: list[str],
    component_markers: list[str],
    config_markers: list[str],
    secret_markers: list[str],
    crypto_markers: list[str],
    negative_evidence: bool,
) -> str:
    if assessment_state == "stack_trace_candidate":
        return (
            f"Route {route_group} exposes verbose error markers ({', '.join(stack_trace_markers[:3])}) and should enter bounded error-disclosure replay."
        )
    if assessment_state == "component_truth_candidate":
        return (
            f"Route {route_group} exposes component-truth markers ({', '.join(component_markers[:3])}) and should enter bounded asset-truth confirmation."
        )
    if assessment_state == "disclosure_candidate":
        return (
            f"Route {route_group} exposes config or secret markers ({', '.join((secret_markers or config_markers)[:3])}) and should enter bounded disclosure replay."
        )
    if assessment_state == "weak_crypto_candidate":
        return (
            f"Route {route_group} exposes crypto-material markers ({', '.join((crypto_markers or secret_markers)[:3])}) and should enter bounded crypto-material review."
        )
    if assessment_state == "misconfiguration_candidate":
        return (
            f"Route {route_group} exposes replayable config/debug pressure and should enter bounded misconfiguration validation."
        )
    if negative_evidence:
        return (
            f"Route {route_group} has disclosure or component pressure but lacks enough route or replay truth. Remaining gaps: {', '.join(evidence_gaps[:3])}."
        )
    if public_surface:
        return f"Route {route_group} is publicly reachable and has weak disclosure pressure that should stay advisory-only until stronger evidence appears."
    return f"Route {route_group} has weak disclosure/misconfiguration signal and should be deprioritized."


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
            "advisory_mode": "disclosure_truth_focus",
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
            "candidate_vulnerability_types": list(item.get("candidate_vulnerability_types") or [])[:4],
            "evidence_gaps": list(item.get("evidence_gaps") or [])[:4],
            "public_surface": bool(item.get("public_surface")),
            "debug_surface": bool(item.get("debug_surface")),
            "config_surface": bool(item.get("config_surface")),
            "component_surface": bool(item.get("component_surface")),
            "secret_surface": bool(item.get("secret_surface")),
            "crypto_surface": bool(item.get("crypto_surface")),
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
        "capability_pack": "p3a_disclosure_misconfig_crypto",
        "advisory_mode": "disclosure_truth_focus",
        "target_profile": target_profile,
        "route_assessment_counts": route_assessment_counts,
        "focus_routes": focus_routes,
        "evidence_gap_summary": evidence_gap_summary,
        "proof_contract_boundary": "advisor_only_no_truth_promotion",
    }
    prompt_contract = advisory_prompt_contract("disclosure_truth_focus")
    user_prompt = build_json_user_prompt(
        prompt_contract,
        preamble=(
            "Review the disclosure, misconfiguration, component-truth, and crypto-material pressure below and recommend which routes, "
            "artifacts, and evidence gaps deserve the next bounded replay pass. Do not certify findings or proof. Optimize only for "
            "route ranking, evidence-gap closure, and target-profile hints."
        ),
        context=context,
    )
    return {
        "enabled": True,
        "advisory_mode": "disclosure_truth_focus",
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


def _challenge_family_for_state(state: str, vulnerability_type: str) -> str:
    if state == "stack_trace_candidate":
        return "observability_failures"
    if state == "component_truth_candidate":
        return "vulnerable_components"
    if state == "weak_crypto_candidate":
        return "cryptographic_issues"
    if vulnerability_type == "openapi_exposure":
        return "security_through_obscurity"
    return "sensitive_data_exposure" if vulnerability_type in {"sensitive_data_exposure", "credential_exposure"} else "security_misconfiguration"


def _looks_like_component_surface(page_url: str, text: str) -> bool:
    lowered_url = page_url.lower()
    return any(token in lowered_url for token in _COMPONENT_ROUTE_HINTS) or any(
        token in text for token in _PUBLIC_ASSET_MARKERS
    )


def _looks_like_openapi(page_url: str, text: str) -> bool:
    lowered_url = page_url.lower()
    return "/openapi" in lowered_url or "/swagger" in lowered_url or ("\"openapi\"" in text and "\"paths\"" in text)


def _looks_like_debug_surface(page_url: str, text: str, *, status_code: int) -> bool:
    lowered_url = page_url.lower()
    return (
        status_code >= 500
        or "/debug" in lowered_url
        or "/internal" in lowered_url
        or bool(_match_markers(text, _STACK_TRACE_MARKERS))
    )


def _component_markers(page_url: str, text: str) -> list[str]:
    markers = [marker for marker in _COMPONENT_MARKER_PATTERNS if marker in text]
    lowered_url = page_url.lower()
    if "/openapi" in lowered_url:
        markers.append("openapi")
    if "/swagger" in lowered_url:
        markers.append("swagger")
    if "/graphql" in lowered_url:
        markers.append("graphql")
    if "/robots.txt" in lowered_url:
        markers.append("robots.txt")
    if "/security.txt" in lowered_url or "/.well-known/" in lowered_url:
        markers.append("security.txt")
    return _dedupe_strings(markers)


def _match_markers(text: str, markers: tuple[str, ...]) -> list[str]:
    return [marker for marker in markers if marker in text]


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
