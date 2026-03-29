"""Safe browser-aware XSS capability analysis and candidate generation."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

import yaml
from pentra_common.ai.prompt_contracts import advisory_prompt_contract, build_json_user_prompt

from .payloads import (
    build_browser_xss_payload_plan,
    load_browser_xss_payload_registry,
    select_browser_xss_payload_archetype,
)

_CAPABILITY_DIR = Path(__file__).resolve().parent
_PENTRA_CORE_DIR = Path(__file__).resolve().parents[6]
_CHEATSHEET_CATALOG_PATH = _PENTRA_CORE_DIR / "knowledge" / "cheatsheets" / "category_catalog.yaml"
_MANIFEST_PATH = _CAPABILITY_DIR / "capability_manifest.yaml"

_SINK_PATTERNS = {
    "innerHTML": r"\.innerhtml\s*=",
    "outerHTML": r"\.outerhtml\s*=",
    "insertAdjacentHTML": r"\.insertadjacenthtml\s*\(",
    "document.write": r"document\.write(?:ln)?\s*\(",
    "srcdoc": r"\.srcdoc\s*=",
    "eval": r"(?<![\w$])eval\s*\(",
    "new Function": r"new function\s*\(",
    "setTimeout-string": r"settimeout\s*\(\s*['\"]",
    "setInterval-string": r"setinterval\s*\(\s*['\"]",
}
_SOURCE_PATTERNS = {
    "location.search": r"location\.search",
    "location.hash": r"location\.hash",
    "location.href": r"location\.href",
    "document.url": r"document\.(?:url|documenturi)",
    "urlsearchparams": r"urlsearchparams\s*\(",
    "decodeURIComponent": r"decodeuricomponent\s*\(",
    "localStorage": r"localstorage(?:\.getitem|\[)",
    "sessionStorage": r"sessionstorage(?:\.getitem|\[)",
    "document.cookie": r"document\.cookie",
}
_PERSISTENT_FIELD_HINTS = {
    "comment",
    "message",
    "review",
    "description",
    "content",
    "feedback",
    "bio",
    "about",
    "title",
}
_XSS_PARAMETER_HINTS = {
    "q",
    "query",
    "search",
    "term",
    "s",
    "message",
    "comment",
    "feedback",
    "name",
    "redirect",
    "returnurl",
}
_EXPLORATORY_ROUTE_PARAMETER_HINTS = {
    "search": ["q", "query", "search"],
    "find": ["q", "query", "search"],
    "login": ["redirect", "returnurl"],
    "signin": ["redirect", "returnurl"],
    "auth": ["redirect", "returnurl"],
    "contact": ["comment", "message", "feedback"],
    "feedback": ["comment", "feedback", "message"],
    "review": ["comment", "review", "message"],
    "comment": ["comment", "message"],
    "message": ["message", "comment"],
    "profile": ["name"],
    "account": ["name"],
}
_GENERIC_EXPLORATORY_PARAMETERS = ["q", "search", "message", "comment", "name", "redirect"]
_PRIVILEGED_ROLE_HINTS = {"admin", "superuser", "root"}


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text()) or {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"Browser XSS capability file must contain a YAML object: {path}")
    return payload


@lru_cache(maxsize=1)
def load_browser_xss_capability_manifest() -> dict[str, Any]:
    return _load_yaml(_MANIFEST_PATH)


@lru_cache(maxsize=1)
def _load_browser_xss_cheatsheet_category() -> dict[str, Any]:
    payload = _load_yaml(_CHEATSHEET_CATALOG_PATH)
    categories = payload.get("categories") or []
    if not isinstance(categories, list):
        raise RuntimeError("Cheat-sheet catalog categories must be a list")
    for category in categories:
        if isinstance(category, dict) and str(category.get("key") or "").strip() == "browser_xss":
            return category
    raise RuntimeError("Cheat-sheet catalog is missing the browser_xss category")


def extract_dom_xss_markers(script_content: str) -> dict[str, list[str]]:
    lowered = script_content.lower()
    sink_markers = [
        label
        for label, pattern in _SINK_PATTERNS.items()
        if re.search(pattern, lowered)
    ]
    source_markers = [
        label
        for label, pattern in _SOURCE_PATTERNS.items()
        if re.search(pattern, lowered)
    ]
    return {
        "sink_markers": sink_markers,
        "source_markers": source_markers,
    }


def build_browser_xss_pack(
    *,
    base_url: str,
    scan_config: dict[str, Any],
    pages: list[dict[str, Any]],
    forms: list[dict[str, Any]],
) -> dict[str, Any]:
    settings = _xss_settings(scan_config)
    manifest = load_browser_xss_capability_manifest()
    cheatsheet = _load_browser_xss_cheatsheet_category()
    payload_registry = load_browser_xss_payload_registry()
    target_profile = _infer_target_profile(pages=pages, forms=forms)
    workflow_stage_counts = {"recon": 0, "analysis": 0, "exploitation_ready": 0}
    route_hints = _route_hints(settings)
    benchmark_inputs_enabled = _benchmark_inputs_enabled(settings)
    max_vectors_per_route = _bounded_int(settings.get("max_vectors_per_route"), default=3, minimum=1, maximum=6)

    if not settings.get("enabled"):
        return {
            "capability_summary": {
                "pack_key": manifest["pack_key"],
                "manifest_name": manifest["name"],
                "enabled": False,
                "target_profile": target_profile,
                "target_profile_keys": list(manifest.get("target_profile_keys") or []),
                "benchmark_target_keys": list(manifest.get("benchmark_target_keys") or []),
                "challenge_family_keys": list(manifest.get("ontology_family_keys") or []),
                "attack_primitive_keys": list(manifest.get("attack_primitive_keys") or []),
                "proof_contract_keys": list(manifest.get("proof_contract_keys") or []),
                "planner_action_keys": list(manifest.get("planner_action_keys") or []),
                "payload_archetype_keys": sorted(payload_registry.get("payload_archetypes_by_key", {}).keys()),
                "planner_hooks": [],
                "negative_evidence": [],
                "advisory_context": {},
                "cheatsheet_entry_keys": _cheatsheet_entry_keys(cheatsheet),
                "benchmark_inputs_enabled": benchmark_inputs_enabled,
                "workflow_stage_counts": workflow_stage_counts,
                "candidate_count": 0,
            },
            "candidates": [],
        }

    page_signal_map = _collect_page_signals(pages)
    configured_forms = _configured_xss_workflow_forms(settings, base_url) if benchmark_inputs_enabled else []
    global_sink_markers = sorted(
        {
            marker
            for signal in page_signal_map.values()
            for marker in signal["sink_markers"]
        }
    )
    global_source_markers = sorted(
        {
            marker
            for signal in page_signal_map.values()
            for marker in signal["source_markers"]
        }
    )
    _inject_workflow_seed_page_signals(
        page_signal_map=page_signal_map,
        configured_forms=configured_forms,
        fallback_sink_markers=global_sink_markers,
        fallback_source_markers=global_source_markers,
    )
    global_sink_markers = sorted(
        {
            marker
            for signal in page_signal_map.values()
            for marker in signal["sink_markers"]
        }
    )
    global_source_markers = sorted(
        {
            marker
            for signal in page_signal_map.values()
            for marker in signal["source_markers"]
        }
    )
    form_map: dict[str, list[dict[str, Any]]] = {}
    for form in [*forms, *configured_forms]:
        page_url = str(form.get("page_url") or "").strip()
        if page_url:
            form_map.setdefault(page_url, []).append(form)

    candidates: list[dict[str, Any]] = []
    candidate_keys: set[str] = set()
    max_candidates = _bounded_int(settings.get("max_candidates"), default=8, minimum=1, maximum=24)

    if benchmark_inputs_enabled:
        for seed_path in _xss_seed_paths(settings):
            request_url = _request_url_for_seed(base_url, seed_path)
            candidate = _build_reflected_or_dom_candidate(
                request_url=request_url,
                page_url=base_url.rstrip("/") + "/",
                route_group=_browser_route_group(request_url),
                target_profile=target_profile,
                route_hints=route_hints,
                sink_markers=global_sink_markers,
                source_markers=global_source_markers,
                direct_sink_markers=[],
                direct_source_markers=[],
                field_names=[],
                requires_auth=False,
                session_labels=[],
                auth_states=[],
                script_evidence_count=0,
                direct_script_evidence_count=0,
                direct_page_count=0,
                cheatsheet=cheatsheet,
                seeded=True,
            )
            if candidate is not None and candidate["candidate_key"] not in candidate_keys:
                candidates.append(candidate)
                candidate_keys.add(candidate["candidate_key"])

    for page_url, signal in page_signal_map.items():
        page_forms = form_map.get(page_url, [])
        if _is_script_surface_url(page_url) and not page_forms:
            continue
        field_names = _candidate_field_names(page_forms)
        route_group = str(signal["route_group"])
        request_urls = _request_urls_from_page(
            page_url=page_url,
            route_group=route_group,
            field_names=field_names,
            source_markers=sorted(signal["source_markers"]),
            max_vectors=max_vectors_per_route,
        )
        for request_url in request_urls:
            candidate = _build_reflected_or_dom_candidate(
                request_url=request_url,
                page_url=page_url,
                route_group=route_group,
                target_profile=target_profile,
                route_hints=route_hints,
                sink_markers=sorted(signal["sink_markers"]),
                source_markers=sorted(signal["source_markers"]),
                direct_sink_markers=sorted(signal["direct_sink_markers"]),
                direct_source_markers=sorted(signal["direct_source_markers"]),
                field_names=field_names,
                requires_auth=bool(signal["requires_auth"]),
                session_labels=sorted(signal["session_labels"]),
                auth_states=sorted(signal["auth_states"]),
                script_evidence_count=int(signal["script_evidence_count"]),
                direct_script_evidence_count=int(signal["direct_script_evidence_count"]),
                direct_page_count=int(signal["direct_page_count"]),
                cheatsheet=cheatsheet,
                seeded=False,
            )
            if candidate is not None and candidate["candidate_key"] not in candidate_keys:
                candidates.append(candidate)
                candidate_keys.add(candidate["candidate_key"])

        for form in page_forms:
            stored_candidate = _build_stored_candidate(
                base_url=base_url,
                form=form,
                page_signal=signal,
                target_profile=target_profile,
                route_hints=route_hints,
                cheatsheet=cheatsheet,
            )
            if stored_candidate is not None and stored_candidate["candidate_key"] not in candidate_keys:
                candidates.append(stored_candidate)
                candidate_keys.add(stored_candidate["candidate_key"])

    ranked_candidates = sorted(candidates, key=_candidate_priority_key)
    deduped_candidates = _select_candidate_subset(ranked_candidates, limit=max_candidates)
    for candidate in deduped_candidates:
        workflow_stage = str(candidate.get("workflow_stage") or "analysis").strip().lower()
        if workflow_stage in workflow_stage_counts:
            workflow_stage_counts[workflow_stage] += 1

    planner_hooks = _build_planner_hooks(deduped_candidates)
    route_assessments = _build_route_assessments(
        page_signal_map=page_signal_map,
        forms_by_page=form_map,
        candidates=deduped_candidates,
        target_profile=target_profile,
        route_hints=route_hints,
    )
    route_assessment_counts = _route_assessment_counts(route_assessments)
    negative_evidence = [
        {
            "route_group": str(item.get("route_group") or ""),
            "assessment_state": str(item.get("assessment_state") or ""),
            "reasoning": str(item.get("reasoning") or ""),
            "evidence_gaps": list(item.get("evidence_gaps") or []),
        }
        for item in route_assessments
        if bool(item.get("negative_evidence"))
    ]
    ai_advisory_bundle = _build_ai_advisory_bundle(
        settings=settings,
        target_profile=target_profile,
        route_hints=route_hints,
        route_assessment_counts=route_assessment_counts,
        route_assessments=route_assessments,
        candidates=deduped_candidates,
    )
    return {
        "capability_summary": {
            "pack_key": manifest["pack_key"],
            "manifest_name": manifest["name"],
            "enabled": True,
            "target_profile": target_profile,
            "target_profile_keys": list(manifest.get("target_profile_keys") or []),
            "benchmark_target_keys": list(manifest.get("benchmark_target_keys") or []),
            "challenge_family_keys": list(manifest.get("ontology_family_keys") or []),
            "attack_primitive_keys": list(manifest.get("attack_primitive_keys") or []),
            "proof_contract_keys": list(manifest.get("proof_contract_keys") or []),
            "planner_action_keys": list(manifest.get("planner_action_keys") or []),
            "payload_archetype_keys": sorted(payload_registry.get("payload_archetypes_by_key", {}).keys()),
            "cheatsheet_entry_keys": _cheatsheet_entry_keys(cheatsheet),
            "planner_hooks": planner_hooks,
            "planner_hook_count": len(planner_hooks),
            "benchmark_inputs_enabled": benchmark_inputs_enabled,
            "workflow_stage_counts": workflow_stage_counts,
            "route_assessment_counts": route_assessment_counts,
            "route_assessments": route_assessments,
            "negative_evidence": negative_evidence,
            "ai_advisory_bundle": ai_advisory_bundle,
            "advisory_context": ai_advisory_bundle,
            "ai_advisory_ready": bool(ai_advisory_bundle.get("enabled")),
            "sink_marker_count": len(global_sink_markers),
            "source_marker_count": len(global_source_markers),
            "candidate_count": len(deduped_candidates),
        },
        "candidates": deduped_candidates,
        "negative_evidence": negative_evidence,
        "advisory_context": ai_advisory_bundle,
    }


def _collect_page_signals(pages: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    page_signal_map: dict[str, dict[str, Any]] = {}
    for page in pages:
        page_url = str(page.get("url") or "").strip()
        if not page_url:
            continue
        synthetic_discovery = bool(page.get("synthetic_discovery"))
        content_type = str(page.get("content_type") or "").strip()
        signal_count = int(page.get("inline_script_count") or 0) + int(page.get("script_signal_count") or 0)
        signal = page_signal_map.setdefault(
            page_url,
            {
                "route_group": page.get("route_group") or _route_group(page_url),
                "sink_markers": set(),
                "source_markers": set(),
                "direct_sink_markers": set(),
                "direct_source_markers": set(),
                "requires_auth": False,
                "session_labels": set(),
                "auth_states": set(),
                "script_evidence_count": 0,
                "direct_script_evidence_count": 0,
                "synthetic_script_evidence_count": 0,
                "direct_page_count": 0,
                "synthetic_discovery_count": 0,
            },
        )
        if synthetic_discovery:
            signal["synthetic_discovery_count"] += 1
        else:
            signal["direct_page_count"] += 1
        for marker in page.get("dom_sink_markers") or []:
            normalized = str(marker).strip()
            if normalized:
                signal["sink_markers"].add(normalized)
                if not synthetic_discovery:
                    signal["direct_sink_markers"].add(normalized)
        for marker in page.get("dom_source_markers") or []:
            normalized = str(marker).strip()
            if normalized:
                signal["source_markers"].add(normalized)
                if not synthetic_discovery:
                    signal["direct_source_markers"].add(normalized)
        if page.get("requires_auth"):
            signal["requires_auth"] = True
        session_label = str(page.get("session_label") or "").strip()
        if session_label:
            signal["session_labels"].add(session_label)
        auth_state = str(page.get("auth_state") or "").strip()
        if auth_state:
            signal["auth_states"].add(auth_state)
        signal["script_evidence_count"] += signal_count
        if synthetic_discovery:
            signal["synthetic_script_evidence_count"] += signal_count
        else:
            signal["direct_script_evidence_count"] += signal_count
        source_url = str(page.get("source_url") or "").strip()
        if source_url and source_url != page_url and _looks_like_script_surface(page_url=page_url, content_type=content_type):
            parent = page_signal_map.setdefault(
                source_url,
                {
                    "route_group": _route_group(source_url),
                    "sink_markers": set(),
                    "source_markers": set(),
                    "direct_sink_markers": set(),
                    "direct_source_markers": set(),
                    "requires_auth": False,
                    "session_labels": set(),
                    "auth_states": set(),
                    "script_evidence_count": 0,
                    "direct_script_evidence_count": 0,
                    "synthetic_script_evidence_count": 0,
                    "direct_page_count": 0,
                    "synthetic_discovery_count": 0,
                },
            )
            parent["sink_markers"].update(signal["sink_markers"])
            parent["source_markers"].update(signal["source_markers"])
            parent["direct_sink_markers"].update(signal["sink_markers"])
            parent["direct_source_markers"].update(signal["source_markers"])
            parent["script_evidence_count"] += int(page.get("script_signal_count") or 0)
            parent["direct_script_evidence_count"] += int(page.get("script_signal_count") or 0)

    for signal in page_signal_map.values():
        auth_states = {str(value).strip().lower() for value in signal.get("auth_states") or [] if str(value).strip()}
        session_labels = {str(value).strip().lower() for value in signal.get("session_labels") or [] if str(value).strip()}
        if "none" in auth_states or "unauthenticated" in session_labels:
            signal["requires_auth"] = False
    return page_signal_map


def _infer_target_profile(*, pages: list[dict[str, Any]], forms: list[dict[str, Any]]) -> str:
    route_groups = {
        str(page.get("route_group") or _route_group(str(page.get("url") or ""))).strip()
        for page in pages
        if str(page.get("url") or "").strip()
    }
    has_hash_routes = any(group.startswith("/#/") or group == "/#" for group in route_groups)
    has_api_surface = any(
        "/api/" in str(page.get("url") or "").lower() or "/rest/" in str(page.get("url") or "").lower()
        for page in pages
    )
    has_dom_sources = any(
        marker in {"location.hash", "location.search", "urlsearchparams", "location.href"}
        for page in pages
        for marker in page.get("dom_source_markers") or []
    )
    has_script_assets = any("javascript" in str(page.get("content_type") or "").lower() for page in pages)
    if has_hash_routes or (has_api_surface and (has_dom_sources or has_script_assets)) or len(forms) <= 1 and has_script_assets:
        return "spa_rest_api"
    return "traditional_server_rendered"


def _xss_settings(scan_config: dict[str, Any]) -> dict[str, Any]:
    stateful = scan_config.get("stateful_testing", {})
    if not isinstance(stateful, dict):
        return {}
    value = stateful.get("xss", {})
    return value if isinstance(value, dict) else {}


def _xss_seed_paths(settings: dict[str, Any]) -> list[str]:
    return _dedupe_strings(_string_list(settings.get("seed_paths")))


def _benchmark_inputs_enabled(settings: dict[str, Any]) -> bool:
    return bool(settings.get("benchmark_inputs_enabled"))


def _configured_xss_workflow_forms(settings: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    seeds = settings.get("workflow_seeds")
    if not isinstance(seeds, list):
        return []

    configured_forms: list[dict[str, Any]] = []
    for seed in seeds:
        if not isinstance(seed, dict):
            continue
        page_url = _join_url(base_url, str(seed.get("page_url") or seed.get("route") or "").strip())
        action_url = _join_url(base_url, str(seed.get("action_url") or "").strip())
        if not page_url or not action_url:
            continue
        route_group = str(seed.get("route_group") or _browser_route_group(page_url)).strip() or _browser_route_group(page_url)
        field_names = _dedupe_strings(_string_list(seed.get("field_names")))
        if not field_names:
            continue
        hidden_fields = _as_dict(seed.get("hidden_fields"))
        rendered_form = {
            "page_url": page_url,
            "route_group": route_group,
            "action_url": action_url,
            "method": str(seed.get("method") or "POST").strip().upper() or "POST",
            "field_names": field_names,
            "hidden_fields": hidden_fields,
            "safe_replay": bool(seed.get("safe_replay", True)),
            "requires_auth": bool(seed.get("requires_auth")),
            "session_label": str(seed.get("session_label") or "").strip(),
            "auth_state": str(seed.get("auth_state") or "").strip(),
            "render_url": _join_url(base_url, str(seed.get("render_url") or page_url).strip()),
            "seed_sink_markers": _dedupe_strings(_string_list(seed.get("sink_markers"))),
            "seed_source_markers": _dedupe_strings(_string_list(seed.get("source_markers"))),
            "script_evidence_count": int(seed.get("script_evidence_count") or 0),
            "workflow_seed": True,
        }
        configured_forms.append(rendered_form)
    return configured_forms


def _inject_workflow_seed_page_signals(
    *,
    page_signal_map: dict[str, dict[str, Any]],
    configured_forms: list[dict[str, Any]],
    fallback_sink_markers: list[str],
    fallback_source_markers: list[str],
) -> None:
    for form in configured_forms:
        page_url = str(form.get("page_url") or "").strip()
        if not page_url:
            continue
        route_group = str(form.get("route_group") or _browser_route_group(page_url)).strip() or _browser_route_group(page_url)
        signal = page_signal_map.setdefault(
            page_url,
            {
                "route_group": route_group,
                "sink_markers": set(),
                "source_markers": set(),
                "direct_sink_markers": set(),
                "direct_source_markers": set(),
                "requires_auth": False,
                "session_labels": set(),
                "auth_states": set(),
                "script_evidence_count": 0,
                "direct_script_evidence_count": 0,
                "synthetic_script_evidence_count": 0,
                "direct_page_count": 0,
                "synthetic_discovery_count": 0,
            },
        )
        seed_sink_markers = _dedupe_strings(
            _string_list(form.get("seed_sink_markers")) or fallback_sink_markers
        )
        seed_source_markers = _dedupe_strings(
            _string_list(form.get("seed_source_markers")) or fallback_source_markers
        )
        signal["sink_markers"].update(seed_sink_markers)
        signal["source_markers"].update(seed_source_markers)
        signal["direct_sink_markers"].update(seed_sink_markers)
        signal["direct_source_markers"].update(seed_source_markers)
        if form.get("requires_auth"):
            signal["requires_auth"] = True
        session_label = str(form.get("session_label") or "").strip()
        if session_label:
            signal["session_labels"].add(session_label)
        auth_state = str(form.get("auth_state") or "").strip()
        if auth_state:
            signal["auth_states"].add(auth_state)
        signal["script_evidence_count"] += int(form.get("script_evidence_count") or 0)
        signal["direct_script_evidence_count"] += int(form.get("script_evidence_count") or 0)
        signal["direct_page_count"] += 1


def _route_hints(settings: dict[str, Any]) -> list[str]:
    return _dedupe_strings(_string_list(settings.get("route_hints")))


def _candidate_field_names(forms: list[dict[str, Any]]) -> list[str]:
    fields = {
        str(field).strip()
        for form in forms
        for field in form.get("field_names") or []
        if _is_xss_candidate_parameter(str(field))
    }
    return sorted(fields)


def _request_url_for_seed(base_url: str, seed_path: str) -> str:
    if seed_path.startswith("http://") or seed_path.startswith("https://"):
        return seed_path
    if seed_path.startswith("/#"):
        return base_url.rstrip("/") + seed_path
    return _join_url(base_url, seed_path)


def _request_urls_from_page(
    *,
    page_url: str,
    route_group: str,
    field_names: list[str],
    source_markers: list[str],
    max_vectors: int,
) -> list[str]:
    parsed = urlparse(page_url)
    query_pairs = list(parse_qsl(parsed.query, keep_blank_values=True))
    request_urls: list[str] = []
    has_fragment_query = bool(parsed.fragment and "?" in parsed.fragment)

    if query_pairs or has_fragment_query:
        request_urls.append(page_url)

    candidate_parameters = _candidate_parameter_names(
        route_group=route_group,
        field_names=field_names,
        source_markers=source_markers,
    )
    if has_fragment_query:
        candidate_parameters = []

    for parameter_name in candidate_parameters:
        if len(request_urls) >= max_vectors:
            break
        if parsed.fragment.startswith("/"):
            fragment_path = parsed.fragment.split("?", 1)[0]
            request_urls.append(
                parsed._replace(fragment=f"{fragment_path}?{urlencode([(parameter_name, 'pentra-canary')])}").geturl()
            )
        else:
            request_urls.append(parsed._replace(query=urlencode([(parameter_name, "pentra-canary")])).geturl())

    return _dedupe_strings(request_urls)[:max_vectors]


def _is_script_surface_url(page_url: str) -> bool:
    path = (urlparse(page_url).path or "").lower()
    return path.endswith(".js") or path.endswith(".mjs")


def _looks_like_script_surface(*, page_url: str, content_type: str) -> bool:
    return _is_script_surface_url(page_url) or "javascript" in content_type.lower()


def _candidate_parameter_names(
    *,
    route_group: str,
    field_names: list[str],
    source_markers: list[str],
) -> list[str]:
    names = list(field_names)
    names.extend(_semantic_route_parameter_names(route_group))

    # Only widen from browser source markers when the route already looks like
    # an input-bearing surface, not for every shared SPA fragment route.
    lowered_route = route_group.strip().lower()
    semantic_match = bool(_semantic_route_parameter_names(route_group))
    if semantic_match and any(marker in {"location.search", "urlsearchparams", "location.href"} for marker in source_markers):
        names.extend(["q", "search", "redirect"])
    if semantic_match and "location.hash" in source_markers:
        names.extend(["q", "view", "redirect"])

    # Keep the root route low-noise unless we already observed input-bearing fields.
    if lowered_route == "/" and field_names:
        names.extend(_GENERIC_EXPLORATORY_PARAMETERS)

    return [name for name in _dedupe_strings(names) if _is_xss_candidate_parameter(name)]


def _semantic_route_parameter_names(route_group: str) -> list[str]:
    route_tokens = _route_tokens(route_group)
    names: list[str] = []
    for route_hint, parameters in _EXPLORATORY_ROUTE_PARAMETER_HINTS.items():
        if _route_hint_matches_tokens(route_hint, route_tokens):
            names.extend(parameters)
    return _dedupe_strings(names)


def _route_tokens(route_group: str) -> set[str]:
    cleaned = route_group.strip().lower().replace("/#/", "/").replace("#", "/")
    return {
        token
        for token in re.split(r"[^a-z0-9]+", cleaned)
        if token
    }


def _route_hint_matches_tokens(route_hint: str, route_tokens: set[str]) -> bool:
    lowered_hint = route_hint.strip().lower()
    if not lowered_hint:
        return False
    return any(
        token == lowered_hint or (token.endswith("s") and token[:-1] == lowered_hint)
        for token in route_tokens
    )


def _exploratory_parameter_names(*, route_group: str, source_markers: list[str]) -> list[str]:
    names: list[str] = _semantic_route_parameter_names(route_group)
    if any(marker in {"location.search", "urlsearchparams", "location.href"} for marker in source_markers):
        names.extend(["q", "search", "redirect"])
    if "location.hash" in source_markers:
        names.extend(["q", "view", "redirect"])
    names.extend(_GENERIC_EXPLORATORY_PARAMETERS)
    return [name for name in _dedupe_strings(names) if _is_xss_candidate_parameter(name)]


def _build_reflected_or_dom_candidate(
    *,
    request_url: str,
    page_url: str,
    route_group: str,
    target_profile: str,
    route_hints: list[str],
    sink_markers: list[str],
    source_markers: list[str],
    direct_sink_markers: list[str],
    direct_source_markers: list[str],
    field_names: list[str],
    requires_auth: bool,
    session_labels: list[str],
    auth_states: list[str],
    script_evidence_count: int,
    direct_script_evidence_count: int,
    direct_page_count: int,
    cheatsheet: dict[str, Any],
    seeded: bool,
) -> dict[str, Any] | None:
    if not sink_markers:
        return None

    candidate_kind, parameter_name = _candidate_from_request_url(request_url)
    if candidate_kind in {"query", "hash_query"} and not parameter_name:
        return None
    if candidate_kind == "query" and parameter_name and not _is_xss_candidate_parameter(parameter_name):
        return None

    attack_primitive = "reflected_xss_route_probe"
    planner_action = "stage_route_specific_xss_payloads"
    if candidate_kind.startswith("hash") or source_markers:
        attack_primitive = "dom_xss_browser_probe"
        planner_action = "map_client_side_sinks"

    workflow_stage = "analysis"
    if seeded or (source_markers and sink_markers and (parameter_name or field_names)):
        workflow_stage = "exploitation_ready"

    workflow_state = _workflow_state_for_route(
        route_group=route_group,
        requires_auth=requires_auth,
        auth_states=auth_states,
        candidate_kind=candidate_kind,
        parameter_name=parameter_name,
    )
    confidence = 68
    if source_markers:
        confidence += 10
    if parameter_name:
        confidence += 8
    if candidate_kind.startswith("hash"):
        confidence += 4
    if direct_script_evidence_count:
        confidence += min(direct_script_evidence_count, 4)
    elif script_evidence_count:
        confidence += min(script_evidence_count, 2)
    route_hint_match = _matches_route_hint(route_group=route_group, page_url=page_url, route_hints=route_hints)
    if parameter_name and not field_names:
        confidence -= 10
    route_local_evidence = bool(direct_source_markers or direct_sink_markers or field_names or direct_page_count > 0)
    if not route_local_evidence:
        confidence -= 6
    route_specific_input = bool(parameter_name or field_names or _semantic_route_parameter_names(route_group))
    if route_group == "/" and not route_specific_input:
        confidence -= 6
    confidence = min(confidence, 89)
    confidence = max(confidence, 40)

    primary_source = source_markers[0] if source_markers else _source_for_candidate_kind(candidate_kind)
    primary_sink = sink_markers[0]
    triggering_condition = _triggering_condition(
        primary_source=primary_source,
        primary_sink=primary_sink,
        route_group=route_group,
        parameter_name=parameter_name,
        candidate_kind=candidate_kind,
    )
    candidate_key = f"{route_group}:{candidate_kind}:{parameter_name or 'fragment'}"
    proof_contract = "browser_execution_xss"
    payload_archetype = select_browser_xss_payload_archetype(
        flow_mode="reflected",
        candidate_kind=candidate_kind,
        target_profile=target_profile,
        source_markers=source_markers,
        sink_markers=sink_markers,
        parameter_name=parameter_name,
        safe_replay=False,
    )
    payload_plan = build_browser_xss_payload_plan(
        archetype=payload_archetype,
        request_url=request_url,
        route_group=route_group,
        flow_mode="reflected",
        candidate_kind=candidate_kind,
        parameter_name=parameter_name,
    )
    payload_archetype_key = str(payload_archetype.get("key") or "").strip()

    evidence_channels = _dedupe_strings(
        [
            "route_local_dom_evidence" if route_local_evidence else "",
            "client_side_source_discovery" if source_markers else "",
            "sink_discovery",
            "browser_verification_ready",
        ]
    )

    return {
        "candidate_key": candidate_key,
        "request_url": request_url,
        "url": request_url,
        "target": request_url,
        "endpoint": request_url,
        "title": "Browser-aware XSS canary candidate",
        "severity": "medium",
        "confidence": confidence,
        "description": (
            "Pentra discovered a client-side source/sink path and staged a benign browser canary verification "
            f"for {route_group}."
        ),
        "tool_source": "web_interact",
        "vulnerability_type": "xss",
        "challenge_family": "xss",
        "attack_primitive": attack_primitive,
        "workflow_state": workflow_state,
        "workflow_stage": workflow_stage,
        "planner_action": planner_action,
        "proof_contract": proof_contract,
        "triggering_condition": triggering_condition,
        "benchmark_route_hint_match": route_hint_match,
        "route_local_evidence": route_local_evidence,
        "evidence_channels": evidence_channels,
        "source": {
            "kind": primary_source,
            "parameter_name": parameter_name,
            "markers": source_markers[:6],
        },
        "sink": {
            "kind": primary_sink,
            "markers": sink_markers[:6],
        },
        "route_context": {
            "page_url": page_url,
            "route_group": route_group,
            "target_profile": target_profile,
            "requires_auth": requires_auth,
            "session_labels": session_labels[:4],
            "auth_states": auth_states[:4],
            "script_evidence_count": script_evidence_count,
            "direct_script_evidence_count": direct_script_evidence_count,
            "direct_page_count": direct_page_count,
            "direct_sink_markers": direct_sink_markers[:6],
            "direct_source_markers": direct_source_markers[:6],
            "route_hint_match": route_hint_match,
        },
        "target_profile": target_profile,
        "capability_pack": "p3a_browser_xss",
        "request": f"GET {request_url}",
        "payload": f"canary_archetype:{payload_archetype_key}",
        "payload_archetype_key": payload_archetype_key,
        "payload_selector": {
            "selected_key": payload_archetype_key,
            "selector_score": payload_archetype.get("selector_score"),
            "matched_source_markers": payload_archetype.get("matched_source_markers") or [],
            "matched_sink_markers": payload_archetype.get("matched_sink_markers") or [],
        },
        "payload_plan": payload_plan,
        "surface": "web",
        "route_group": route_group,
        "verification_state": "suspected",
        "verification_confidence": confidence,
        "references": [f"sink:{marker}" for marker in sink_markers[:4]]
        + [f"source:{marker}" for marker in source_markers[:4]]
        + [
            f"proof_contract:{proof_contract}",
            f"planner_action:{planner_action}",
            f"payload_archetype:{payload_archetype_key}",
        ],
        "cheatsheet_entry_keys": _cheatsheet_entry_keys(cheatsheet),
        "planner_hook": {
            "action_type": planner_action,
            "route_group": route_group,
            "objective": "Map client-side browser sink flow and verify benign canary propagation.",
            "target_profile": target_profile,
            "preferred_tool_ids": ["web_interact", "custom_poc"],
        },
        "verification_context": {
            "verify_type": "xss_browser",
            "flow_mode": "reflected",
            "page_url": page_url,
            "request_url": request_url,
            "route_group": route_group,
            "candidate_kind": candidate_kind,
            "parameter_name": parameter_name,
            "sink_markers": sink_markers[:6],
            "source_markers": source_markers[:6],
            "field_names": field_names[:8],
            "proof_contract": proof_contract,
            "planner_action": planner_action,
            "attack_primitive": attack_primitive,
            "challenge_family": "xss",
            "workflow_state": workflow_state,
            "workflow_stage": workflow_stage,
            "target_profile": target_profile,
            "triggering_condition": triggering_condition,
            "route_hint_match": route_hint_match,
            "route_local_evidence": route_local_evidence,
            "evidence_channels": evidence_channels,
            "cheatsheet_entry_keys": _cheatsheet_entry_keys(cheatsheet),
            "payload_archetype_key": payload_archetype_key,
            "payload_selector": {
                "selected_key": payload_archetype_key,
                "selector_score": payload_archetype.get("selector_score"),
                "matched_source_markers": payload_archetype.get("matched_source_markers") or [],
                "matched_sink_markers": payload_archetype.get("matched_sink_markers") or [],
            },
            "payload_plan": payload_plan,
        },
    }


def _build_stored_candidate(
    *,
    base_url: str,
    form: dict[str, Any],
    page_signal: dict[str, Any],
    target_profile: str,
    route_hints: list[str],
    cheatsheet: dict[str, Any],
) -> dict[str, Any] | None:
    if not bool(form.get("safe_replay")):
        return None
    field_names = [str(field).strip() for field in form.get("field_names") or [] if str(field).strip()]
    persistent_fields = [
        field
        for field in field_names
        if field.strip().lower() in _PERSISTENT_FIELD_HINTS
    ]
    if not persistent_fields:
        return None
    sink_markers = sorted(page_signal.get("sink_markers") or [])
    if not sink_markers:
        return None

    page_url = str(form.get("page_url") or "").strip() or base_url
    action_url = str(form.get("action_url") or "").strip() or page_url
    render_url = str(form.get("render_url") or "").strip() or page_url
    method = str(form.get("method") or "POST").strip().upper()
    field_name = persistent_fields[0]
    route_group = str(form.get("route_group") or page_signal.get("route_group") or _route_group(page_url))
    requires_auth = bool(form.get("requires_auth")) or bool(page_signal.get("requires_auth"))
    auth_states = sorted(page_signal.get("auth_states") or [])
    workflow_state = _stored_workflow_state(route_group=route_group, requires_auth=requires_auth, auth_states=auth_states)
    confidence = 74 + min(len(sink_markers), 3)
    route_hint_match = _matches_route_hint(route_group=route_group, page_url=page_url, route_hints=route_hints)
    triggering_condition = (
        f"Benign canary submitted through persistent field '{field_name}' should later render on {route_group} "
        f"and reach {sink_markers[0]}."
    )
    candidate_key = f"{route_group}:stored_form:{field_name}"
    proof_contract = "stored_execution_xss"
    payload_archetype = select_browser_xss_payload_archetype(
        flow_mode="stored",
        candidate_kind="stored_form",
        target_profile=target_profile,
        source_markers=["persistent_form_field"],
        sink_markers=sink_markers,
        parameter_name=field_name,
        safe_replay=True,
    )
    payload_plan = build_browser_xss_payload_plan(
        archetype=payload_archetype,
        request_url=page_url,
        route_group=route_group,
        flow_mode="stored",
        candidate_kind="stored_form",
        parameter_name=field_name,
        form_action_url=action_url,
        form_method=method,
        render_url=render_url,
        hidden_fields=_as_dict(form.get("hidden_fields")),
    )
    payload_archetype_key = str(payload_archetype.get("key") or "").strip()

    return {
        "candidate_key": candidate_key,
        "request_url": page_url,
        "url": page_url,
        "target": page_url,
        "endpoint": page_url,
        "title": "Stored browser XSS canary candidate",
        "severity": "medium",
        "confidence": min(confidence, 90),
        "description": (
            "Pentra identified a safe replay form with a persistent-looking field and staged a benign stored "
            "browser canary flow."
        ),
        "tool_source": "web_interact",
        "vulnerability_type": "xss",
        "challenge_family": "xss",
        "attack_primitive": "stored_xss_workflow_probe",
        "workflow_state": workflow_state,
        "workflow_stage": "exploitation_ready",
        "planner_action": "replay_stored_xss_workflow",
        "proof_contract": proof_contract,
        "triggering_condition": triggering_condition,
        "benchmark_route_hint_match": route_hint_match,
        "route_local_evidence": True,
        "evidence_channels": _dedupe_strings(
            [
                "route_local_dom_evidence",
                "stored_form_replay",
                "sink_discovery",
                "browser_verification_ready",
            ]
        ),
        "source": {
            "kind": "persistent_form_field",
            "parameter_name": field_name,
            "markers": [field_name],
        },
        "sink": {
            "kind": sink_markers[0],
            "markers": sink_markers[:6],
        },
        "route_context": {
            "page_url": page_url,
            "form_action_url": action_url,
            "render_url": render_url,
            "route_group": route_group,
            "target_profile": target_profile,
            "requires_auth": requires_auth,
            "session_label": str(form.get("session_label") or ""),
            "route_hint_match": route_hint_match,
        },
        "target_profile": target_profile,
        "capability_pack": "p3a_browser_xss",
        "request": f"{method} {action_url}",
        "payload": f"canary_archetype:{payload_archetype_key}",
        "payload_archetype_key": payload_archetype_key,
        "payload_selector": {
            "selected_key": payload_archetype_key,
            "selector_score": payload_archetype.get("selector_score"),
            "matched_source_markers": payload_archetype.get("matched_source_markers") or [],
            "matched_sink_markers": payload_archetype.get("matched_sink_markers") or [],
        },
        "payload_plan": payload_plan,
        "surface": "web",
        "route_group": route_group,
        "verification_state": "suspected",
        "verification_confidence": min(confidence, 90),
        "references": [f"sink:{marker}" for marker in sink_markers[:4]]
        + [
            f"form_field:{field_name}",
            f"proof_contract:{proof_contract}",
            "safe_replay:true",
            f"payload_archetype:{payload_archetype_key}",
        ],
        "cheatsheet_entry_keys": _cheatsheet_entry_keys(cheatsheet),
        "planner_hook": {
            "action_type": "replay_stored_xss_workflow",
            "route_group": route_group,
            "objective": "Replay stored canary content and observe dangerous browser sink activation.",
            "target_profile": target_profile,
            "preferred_tool_ids": ["web_interact", "custom_poc"],
        },
        "verification_context": {
            "verify_type": "xss_browser",
            "flow_mode": "stored",
            "request_url": page_url,
            "render_url": render_url,
            "page_url": page_url,
            "route_group": route_group,
            "candidate_kind": "stored_form",
            "parameter_name": field_name,
            "form_action_url": action_url,
            "form_method": method,
            "form_hidden_fields": _as_dict(form.get("hidden_fields")),
            "sink_markers": sink_markers[:6],
            "source_markers": [field_name],
            "field_names": field_names[:8],
            "proof_contract": proof_contract,
            "planner_action": "replay_stored_xss_workflow",
            "attack_primitive": "stored_xss_workflow_probe",
            "challenge_family": "xss",
            "workflow_state": workflow_state,
            "workflow_stage": "exploitation_ready",
            "target_profile": target_profile,
            "triggering_condition": triggering_condition,
            "route_hint_match": route_hint_match,
            "cheatsheet_entry_keys": _cheatsheet_entry_keys(cheatsheet),
            "payload_archetype_key": payload_archetype_key,
            "payload_selector": {
                "selected_key": payload_archetype_key,
                "selector_score": payload_archetype.get("selector_score"),
                "matched_source_markers": payload_archetype.get("matched_source_markers") or [],
                "matched_sink_markers": payload_archetype.get("matched_sink_markers") or [],
            },
            "payload_plan": payload_plan,
        },
    }


def _candidate_priority_key(candidate: dict[str, Any]) -> tuple[Any, ...]:
    verification_context = candidate.get("verification_context") or {}
    field_names = verification_context.get("field_names") or []
    return (
        -int(str(candidate.get("proof_contract") or "").strip() == "stored_execution_xss"),
        -int(bool(candidate.get("route_local_evidence"))),
        -int(str(candidate.get("route_group") or "").strip() != "/"),
        -int(str(candidate.get("workflow_stage") or "").strip() == "exploitation_ready"),
        -len(field_names) if isinstance(field_names, list) else 0,
        -int(candidate.get("confidence") or 0),
        -int(candidate.get("verification_confidence") or 0),
        str(candidate.get("route_group") or ""),
        str(candidate.get("candidate_key") or ""),
    )


def _select_candidate_subset(candidates: list[dict[str, Any]], *, limit: int) -> list[dict[str, Any]]:
    if limit <= 0:
        return []

    selected: list[dict[str, Any]] = []
    seen_slots: set[tuple[str, str]] = set()
    route_counts: dict[str, int] = {}

    for candidate in candidates:
        route_group = str(candidate.get("route_group") or "").strip()
        proof_contract = str(candidate.get("proof_contract") or "").strip()
        slot = (route_group, proof_contract)
        if slot in seen_slots:
            continue
        selected.append(candidate)
        seen_slots.add(slot)
        route_counts[route_group] = route_counts.get(route_group, 0) + 1
        if len(selected) >= limit:
            return selected

    for candidate in candidates:
        if candidate in selected:
            continue
        route_group = str(candidate.get("route_group") or "").strip()
        if route_counts.get(route_group, 0) >= 2:
            continue
        selected.append(candidate)
        route_counts[route_group] = route_counts.get(route_group, 0) + 1
        if len(selected) >= limit:
            return selected

    for candidate in candidates:
        if candidate in selected:
            continue
        selected.append(candidate)
        if len(selected) >= limit:
            break
    return selected[:limit]


def _build_planner_hooks(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hooks: dict[tuple[str, str], dict[str, Any]] = {}
    for candidate in candidates:
        planner_hook = candidate.get("planner_hook")
        if not isinstance(planner_hook, dict):
            continue
        action_type = str(planner_hook.get("action_type") or "").strip()
        route_group = str(planner_hook.get("route_group") or candidate.get("route_group") or "").strip()
        if not action_type or not route_group:
            continue
        key = (action_type, route_group)
        hooks.setdefault(
            key,
            {
                "action_type": action_type,
                "route_group": route_group,
                "objective": planner_hook.get("objective"),
                "target_profile": planner_hook.get("target_profile"),
                "preferred_tool_ids": planner_hook.get("preferred_tool_ids") or [],
                "candidate_count": 0,
                "proof_contracts": set(),
            },
        )
        hooks[key]["candidate_count"] += 1
        proof_contract = str(candidate.get("proof_contract") or "").strip()
        if proof_contract:
            hooks[key]["proof_contracts"].add(proof_contract)
    return [
        {
            **value,
            "proof_contracts": sorted(value["proof_contracts"]),
        }
        for value in hooks.values()
    ]


def _build_route_assessments(
    *,
    page_signal_map: dict[str, dict[str, Any]],
    forms_by_page: dict[str, list[dict[str, Any]]],
    candidates: list[dict[str, Any]],
    target_profile: str,
    route_hints: list[str],
) -> list[dict[str, Any]]:
    candidate_counts: dict[str, int] = {}
    candidate_primitives: dict[str, set[str]] = {}
    proof_contracts: dict[str, set[str]] = {}
    for candidate in candidates:
        route_group = str(candidate.get("route_group") or "").strip()
        if not route_group:
            continue
        candidate_counts[route_group] = candidate_counts.get(route_group, 0) + 1
        primitive = str(candidate.get("attack_primitive") or "").strip()
        if primitive:
            candidate_primitives.setdefault(route_group, set()).add(primitive)
        proof_contract = str(candidate.get("proof_contract") or "").strip()
        if proof_contract:
            proof_contracts.setdefault(route_group, set()).add(proof_contract)

    assessments: list[dict[str, Any]] = []
    assessed_route_groups: set[str] = set()
    for page_url, signal in page_signal_map.items():
        if _is_script_surface_url(page_url):
            continue
        route_group = str(signal.get("route_group") or _route_group(page_url)).strip() or "/"
        assessed_route_groups.add(route_group)
        sink_markers = sorted(signal.get("sink_markers") or [])
        source_markers = sorted(signal.get("source_markers") or [])
        direct_sink_markers = sorted(signal.get("direct_sink_markers") or [])
        direct_source_markers = sorted(signal.get("direct_source_markers") or [])
        page_forms = forms_by_page.get(page_url, [])
        field_names = _candidate_field_names(page_forms)
        parameter_hypotheses = _parameter_hypotheses(
            route_group=route_group,
            field_names=field_names,
            source_markers=source_markers,
        )
        candidate_count = candidate_counts.get(route_group, 0)
        route_hint_match = _matches_route_hint(route_group=route_group, page_url=page_url, route_hints=route_hints)
        route_local_evidence = bool(
            direct_sink_markers
            or direct_source_markers
            or field_names
            or int(signal.get("direct_page_count") or 0) > 0
        )
        state, next_action = _route_assessment_state(
            candidate_count=candidate_count,
            sink_markers=sink_markers,
            source_markers=source_markers,
            field_names=field_names,
        )
        risk_score = _route_risk_score(
            candidate_count=candidate_count,
            sink_markers=sink_markers,
            source_markers=source_markers,
            field_names=field_names,
            requires_auth=bool(signal.get("requires_auth")),
            script_evidence_count=int(signal.get("direct_script_evidence_count") or 0),
            route_local_evidence=route_local_evidence,
        )
        assessments.append(
            {
                "route_group": route_group,
                "page_url": page_url,
                "target_profile": target_profile,
                "assessment_state": state,
                "risk_score": risk_score,
                "candidate_count": candidate_count,
                "source_marker_count": len(source_markers),
                "sink_marker_count": len(sink_markers),
                "form_count": len(page_forms),
                "direct_sink_marker_count": len(direct_sink_markers),
                "direct_source_marker_count": len(direct_source_markers),
                "candidate_field_names": field_names[:8],
                "parameter_hypotheses": parameter_hypotheses[:8],
                "route_hint_match": route_hint_match,
                "route_local_evidence": route_local_evidence,
                "sink_markers": sink_markers[:8],
                "source_markers": source_markers[:8],
                "direct_sink_markers": direct_sink_markers[:8],
                "direct_source_markers": direct_source_markers[:8],
                "requires_auth": bool(signal.get("requires_auth")),
                "session_labels": sorted(signal.get("session_labels") or [])[:4],
                "auth_states": sorted(signal.get("auth_states") or [])[:4],
                "script_evidence_count": int(signal.get("script_evidence_count") or 0),
                "direct_script_evidence_count": int(signal.get("direct_script_evidence_count") or 0),
                "synthetic_script_evidence_count": int(signal.get("synthetic_script_evidence_count") or 0),
                "direct_page_count": int(signal.get("direct_page_count") or 0),
                "synthetic_discovery_count": int(signal.get("synthetic_discovery_count") or 0),
                "attack_primitives": sorted(candidate_primitives.get(route_group) or []),
                "proof_contracts": sorted(proof_contracts.get(route_group) or []),
                "next_action": next_action,
                "evidence_gaps": _route_evidence_gaps(
                    state=state,
                    candidate_count=candidate_count,
                    parameter_hypotheses=parameter_hypotheses,
                    requires_auth=bool(signal.get("requires_auth")),
                    route_local_evidence=route_local_evidence,
                ),
                "advisory_priority": _route_advisory_priority(
                    state=state,
                    risk_score=risk_score,
                    candidate_count=candidate_count,
                    route_local_evidence=route_local_evidence,
                ),
                "negative_evidence": state in {"source_only", "sink_only", "low_signal"},
                "reasoning": _route_assessment_reasoning(
                    route_group=route_group,
                    state=state,
                    sink_markers=sink_markers,
                    source_markers=source_markers,
                    field_names=field_names,
                    candidate_count=candidate_count,
                    route_local_evidence=route_local_evidence,
                ),
            }
        )

    synthesized_by_route: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        route_group = str(candidate.get("route_group") or "").strip()
        if not route_group or route_group in assessed_route_groups:
            continue
        page_url = str(
            ((candidate.get("route_context") or {}).get("page_url"))
            or candidate.get("request_url")
            or candidate.get("url")
            or ""
        ).strip()
        source_markers = _dedupe_strings(
            [
                str(((candidate.get("source") or {}).get("kind") or "")).strip(),
                *[
                    str(value).strip()
                    for value in (((candidate.get("source") or {}).get("markers")) or [])
                    if str(value).strip()
                ],
            ]
        )
        sink_markers = _dedupe_strings(
            [
                str(((candidate.get("sink") or {}).get("kind") or "")).strip(),
                *[
                    str(value).strip()
                    for value in (((candidate.get("sink") or {}).get("markers")) or [])
                    if str(value).strip()
                ],
            ]
        )
        parameter_name = str(((candidate.get("source") or {}).get("parameter_name") or "")).strip()
        field_names = [parameter_name] if parameter_name else []
        parameter_hypotheses = _parameter_hypotheses(
            route_group=route_group,
            field_names=field_names,
            source_markers=source_markers,
        )
        route_hint_match = bool(candidate.get("benchmark_route_hint_match"))
        route_context = candidate.get("route_context") or {}
        requires_auth = bool(route_context.get("requires_auth"))
        session_labels = [str(value).strip() for value in (route_context.get("session_labels") or []) if str(value).strip()]
        auth_states = [str(value).strip() for value in (route_context.get("auth_states") or []) if str(value).strip()]
        script_evidence_count = int(route_context.get("script_evidence_count") or 0)
        direct_script_evidence_count = int(route_context.get("direct_script_evidence_count") or 0)
        direct_page_count = int(route_context.get("direct_page_count") or 0)
        direct_sink_markers = _dedupe_strings(_string_list(route_context.get("direct_sink_markers")))
        direct_source_markers = _dedupe_strings(_string_list(route_context.get("direct_source_markers")))
        candidate_count = candidate_counts.get(route_group, 0)
        route_local_evidence = bool(
            candidate.get("route_local_evidence")
            or direct_sink_markers
            or direct_source_markers
            or field_names
            or direct_page_count > 0
        )
        state, next_action = _route_assessment_state(
            candidate_count=candidate_count,
            sink_markers=sink_markers,
            source_markers=source_markers,
            field_names=field_names,
        )
        risk_score = _route_risk_score(
            candidate_count=candidate_count,
            sink_markers=sink_markers,
            source_markers=source_markers,
            field_names=field_names,
            requires_auth=requires_auth,
            script_evidence_count=direct_script_evidence_count or script_evidence_count,
            route_local_evidence=route_local_evidence,
        )
        existing = synthesized_by_route.get(route_group)
        if existing and int(existing.get("risk_score") or 0) >= risk_score:
            continue
        synthesized_by_route[route_group] = {
            "route_group": route_group,
            "page_url": page_url,
            "target_profile": target_profile,
            "assessment_state": state,
            "risk_score": risk_score,
            "candidate_count": candidate_count,
            "source_marker_count": len(source_markers),
            "sink_marker_count": len(sink_markers),
            "form_count": 0,
            "direct_sink_marker_count": len(direct_sink_markers),
            "direct_source_marker_count": len(direct_source_markers),
            "candidate_field_names": field_names[:8],
            "parameter_hypotheses": parameter_hypotheses[:8],
            "route_hint_match": route_hint_match,
            "route_local_evidence": route_local_evidence,
            "sink_markers": sink_markers[:8],
            "source_markers": source_markers[:8],
            "direct_sink_markers": direct_sink_markers[:8],
            "direct_source_markers": direct_source_markers[:8],
            "requires_auth": requires_auth,
            "session_labels": sorted(session_labels)[:4],
            "auth_states": sorted(auth_states)[:4],
            "script_evidence_count": script_evidence_count,
            "direct_script_evidence_count": direct_script_evidence_count,
            "synthetic_script_evidence_count": 0,
            "direct_page_count": direct_page_count,
            "synthetic_discovery_count": 0,
            "attack_primitives": sorted(candidate_primitives.get(route_group) or []),
            "proof_contracts": sorted(proof_contracts.get(route_group) or []),
            "next_action": next_action,
            "evidence_gaps": _route_evidence_gaps(
                state=state,
                candidate_count=candidate_count,
                parameter_hypotheses=parameter_hypotheses,
                requires_auth=requires_auth,
                route_local_evidence=route_local_evidence,
            ),
            "advisory_priority": _route_advisory_priority(
                state=state,
                risk_score=risk_score,
                candidate_count=candidate_count,
                route_local_evidence=route_local_evidence,
            ),
            "negative_evidence": state in {"source_only", "sink_only", "low_signal"},
            "reasoning": _route_assessment_reasoning(
                route_group=route_group,
                state=state,
                sink_markers=sink_markers,
                source_markers=source_markers,
                field_names=field_names,
                candidate_count=candidate_count,
                route_local_evidence=route_local_evidence,
            ),
        }

    assessments.extend(synthesized_by_route.values())

    return sorted(
        assessments,
        key=lambda item: (
            -int(item.get("advisory_priority") or 0),
            -int(item.get("risk_score") or 0),
            -int(item.get("candidate_count") or 0),
            str(item.get("route_group") or ""),
        ),
    )


def _route_assessment_state(
    *,
    candidate_count: int,
    sink_markers: list[str],
    source_markers: list[str],
    field_names: list[str],
) -> tuple[str, str]:
    if candidate_count > 0:
        return "candidate_ready", "verify_browser_flow"
    if sink_markers and source_markers:
        return "sink_and_source_unbound", "focus_route_analysis"
    if sink_markers and field_names:
        return "sink_only", "search_for_input_binding"
    if source_markers:
        return "source_only", "search_for_dangerous_sink"
    return "low_signal", "deprioritize_route"


def _route_risk_score(
    *,
    candidate_count: int,
    sink_markers: list[str],
    source_markers: list[str],
    field_names: list[str],
    requires_auth: bool,
    script_evidence_count: int,
    route_local_evidence: bool,
) -> int:
    score = 0
    score += candidate_count * 35
    score += min(len(sink_markers), 4) * 10
    score += min(len(source_markers), 4) * 7
    score += min(len(field_names), 3) * 5
    score += min(script_evidence_count, 5) * 3
    if requires_auth:
        score += 4
    if route_local_evidence:
        score += 6
    elif candidate_count == 0:
        score = max(score - 12, 0)
    return min(score, 100)


def _route_assessment_reasoning(
    *,
    route_group: str,
    state: str,
    sink_markers: list[str],
    source_markers: list[str],
    field_names: list[str],
    candidate_count: int,
    route_local_evidence: bool,
) -> str:
    provenance_text = "" if route_local_evidence else " Current signal is shared browser-script evidence, not route-local DOM evidence."
    if state == "candidate_ready":
        return (
            f"Route {route_group} already has {candidate_count} browser-XSS candidate(s) with aligned "
            f"source markers ({', '.join(source_markers[:3]) or 'none'}) and sink markers "
            f"({', '.join(sink_markers[:3]) or 'none'}).{provenance_text}"
        )
    if state == "sink_and_source_unbound":
        return (
            f"Route {route_group} exposes both source markers ({', '.join(source_markers[:3])}) and "
            f"sink markers ({', '.join(sink_markers[:3])}) but lacks a clear input binding.{provenance_text}"
        )
    if state == "sink_only":
        return (
            f"Route {route_group} exposes sink markers ({', '.join(sink_markers[:3])}) and candidate input "
            f"fields ({', '.join(field_names[:3]) or 'none'}) but no strong client-side source markers yet.{provenance_text}"
        )
    if state == "source_only":
        return (
            f"Route {route_group} exposes browser input sources ({', '.join(source_markers[:3])}) without a "
            f"corresponding dangerous sink.{provenance_text}"
        )
    return f"Route {route_group} has weak browser-XSS signal and should be deprioritized for now.{provenance_text}"


def _parameter_hypotheses(
    *,
    route_group: str,
    field_names: list[str],
    source_markers: list[str],
) -> list[str]:
    return _dedupe_strings(
        [
            *field_names,
            *_exploratory_parameter_names(route_group=route_group, source_markers=source_markers),
        ]
    )


def _route_evidence_gaps(
    *,
    state: str,
    candidate_count: int,
    parameter_hypotheses: list[str],
    requires_auth: bool,
    route_local_evidence: bool,
) -> list[str]:
    gaps: list[str] = []
    if state == "candidate_ready" and candidate_count > 0:
        gaps.append("verification")
    elif state == "sink_and_source_unbound":
        gaps.append("input_binding")
        if parameter_hypotheses:
            gaps.append("route_parameter_selection")
    elif state == "sink_only":
        gaps.append("browser_source_mapping")
    elif state == "source_only":
        gaps.append("dangerous_sink_mapping")
    else:
        gaps.append("signal_strength")
    if not route_local_evidence:
        gaps.append("route_local_evidence")
    if requires_auth:
        gaps.append("auth_context")
    return _dedupe_strings(gaps)


def _route_advisory_priority(
    *,
    state: str,
    risk_score: int,
    candidate_count: int,
    route_local_evidence: bool,
) -> int:
    priority = int(risk_score)
    if state == "candidate_ready":
        priority += 18
    elif state == "sink_and_source_unbound":
        priority += 10
    elif state == "source_only":
        priority += 4
    priority += min(candidate_count, 3) * 3
    if not route_local_evidence and candidate_count == 0:
        priority = max(priority - 12, 0)
    return min(priority, 100)


def _build_ai_advisory_bundle(
    *,
    settings: dict[str, Any],
    target_profile: str,
    route_hints: list[str],
    route_assessment_counts: dict[str, int],
    route_assessments: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    if settings.get("ai_advisory_enabled") is False:
        return {
            "enabled": False,
            "advisory_mode": "browser_xss_route_focus",
            "prompt_contract": None,
            "focus_routes": [],
            "candidate_preview": [],
            "evidence_gap_summary": [],
            "user_prompt": "",
        }

    focus_route_limit = _bounded_int(settings.get("ai_focus_route_limit"), default=5, minimum=1, maximum=8)
    focus_routes = [
        {
            "route_group": str(item.get("route_group") or ""),
            "page_url": str(item.get("page_url") or ""),
            "assessment_state": str(item.get("assessment_state") or ""),
            "risk_score": int(item.get("risk_score") or 0),
            "advisory_priority": int(item.get("advisory_priority") or 0),
            "candidate_count": int(item.get("candidate_count") or 0),
            "parameter_hypotheses": list(item.get("parameter_hypotheses") or [])[:5],
            "proof_contracts": list(item.get("proof_contracts") or [])[:3],
            "evidence_gaps": list(item.get("evidence_gaps") or [])[:4],
            "next_action": str(item.get("next_action") or ""),
            "reasoning": str(item.get("reasoning") or ""),
        }
        for item in route_assessments[:focus_route_limit]
    ]
    candidate_preview = [
        {
            "route_group": str(item.get("route_group") or ""),
            "request_url": str(item.get("request_url") or item.get("url") or ""),
            "attack_primitive": str(item.get("attack_primitive") or ""),
            "proof_contract": str(item.get("proof_contract") or ""),
            "confidence": int(item.get("confidence") or 0),
            "triggering_condition": str(item.get("triggering_condition") or ""),
        }
        for item in candidates[:focus_route_limit]
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
        "capability_pack": "p3a_browser_xss",
        "advisory_mode": "browser_xss_route_focus",
        "target_profile": target_profile,
        "benchmark_metadata": {
            "route_hint_count": len(route_hints),
            "route_hint_matches": int(route_assessment_counts.get("route_hint_matches") or 0),
        },
        "route_assessment_counts": route_assessment_counts,
        "focus_routes": focus_routes,
        "candidate_preview": candidate_preview,
        "evidence_gap_summary": evidence_gap_summary,
        "proof_contract_boundary": "advisor_only_no_truth_promotion",
    }
    prompt_contract = advisory_prompt_contract("browser_xss_route_focus")
    user_prompt = build_json_user_prompt(
        prompt_contract,
        preamble=(
            "Review the browser-XSS route pressure below and recommend which route groups deserve the next "
            "safe browser-analysis pass. Do not certify findings or proof. Optimize only for route prioritization, "
            "parameter hypotheses, and evidence-gap closure."
        ),
        context=context,
    )
    return {
        "enabled": True,
        "advisory_mode": "browser_xss_route_focus",
        "prompt_contract": {
            "contract_id": prompt_contract.contract_id,
            "prompt_version": prompt_contract.prompt_version,
            "task_type": prompt_contract.task_type,
            "response_format": prompt_contract.response_format,
        },
        "focus_routes": focus_routes,
        "candidate_preview": candidate_preview,
        "evidence_gap_summary": evidence_gap_summary,
        "user_prompt": user_prompt,
    }


def _route_assessment_counts(route_assessments: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "candidate_ready": 0,
        "sink_and_source_unbound": 0,
        "sink_only": 0,
        "source_only": 0,
        "low_signal": 0,
        "negative_evidence_routes": 0,
        "route_hint_matches": 0,
    }
    for assessment in route_assessments:
        state = str(assessment.get("assessment_state") or "").strip()
        if state in counts:
            counts[state] += 1
        if bool(assessment.get("negative_evidence")):
            counts["negative_evidence_routes"] += 1
        if bool(assessment.get("route_hint_match")):
            counts["route_hint_matches"] += 1
    return counts


def _matches_route_hint(*, route_group: str, page_url: str, route_hints: list[str]) -> bool:
    if not route_hints:
        return False
    lowered_route = route_group.strip().lower()
    lowered_url = page_url.strip().lower()
    return any(
        hint and (hint in lowered_route or hint in lowered_url)
        for hint in (item.strip().lower() for item in route_hints)
    )


def summarize_browser_xss_verification_feedback(
    *,
    candidates: list[dict[str, Any]],
    verification_outcomes: list[dict[str, Any]],
    verified_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    outcome_by_request: dict[str, dict[str, Any]] = {}
    outcome_by_slot: dict[tuple[str, str], dict[str, Any]] = {}
    for outcome in verification_outcomes:
        if not isinstance(outcome, dict):
            continue
        request_url = str(outcome.get("request_url") or "").strip()
        route_group = str(outcome.get("route_group") or "").strip()
        proof_contract = str(outcome.get("proof_contract") or "").strip()
        if request_url:
            outcome_by_request[request_url] = outcome
        if route_group and proof_contract:
            outcome_by_slot[(route_group, proof_contract)] = outcome

    verified_routes = {
        str(item.get("route_group") or "").strip()
        for item in verified_findings
        if isinstance(item, dict) and str(item.get("verification_state") or "").strip() == "verified"
    }
    candidate_reviews: list[dict[str, Any]] = []
    counts = {
        "verified": 0,
        "no_observation": 0,
        "error": 0,
        "not_attempted": 0,
        "demoted": 0,
    }
    demoted_routes: dict[str, dict[str, Any]] = {}

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        request_url = str(candidate.get("request_url") or candidate.get("url") or "").strip()
        route_group = str(candidate.get("route_group") or "").strip()
        proof_contract = str(candidate.get("proof_contract") or "").strip()
        outcome = outcome_by_request.get(request_url) or outcome_by_slot.get((route_group, proof_contract))
        verification_state = str((outcome or {}).get("verification_state") or "not_attempted").strip() or "not_attempted"
        demoted = verification_state == "no_observation" and route_group not in verified_routes
        counts[verification_state] = counts.get(verification_state, 0) + 1
        if demoted:
            counts["demoted"] += 1
            demoted_routes.setdefault(
                route_group,
                {
                    "route_group": route_group,
                    "proof_contracts": set(),
                    "request_urls": set(),
                    "reason": "no_observation_after_replay",
                },
            )
            demoted_routes[route_group]["proof_contracts"].add(proof_contract)
            if request_url:
                demoted_routes[route_group]["request_urls"].add(request_url)
        candidate_reviews.append(
            {
                "candidate_key": str(candidate.get("candidate_key") or "").strip(),
                "route_group": route_group,
                "proof_contract": proof_contract,
                "request_url": request_url,
                "post_verification_state": verification_state,
                "demoted": demoted,
                "route_local_evidence": bool(candidate.get("route_local_evidence")),
            }
        )

    return {
        "verification_counts": counts,
        "verified_routes": sorted(route for route in verified_routes if route),
        "demoted_routes": [
            {
                **value,
                "proof_contracts": sorted(value["proof_contracts"]),
                "request_urls": sorted(value["request_urls"]),
            }
            for value in demoted_routes.values()
        ],
        "candidate_reviews": candidate_reviews,
    }


def _triggering_condition(
    *,
    primary_source: str,
    primary_sink: str,
    route_group: str,
    parameter_name: str | None,
    candidate_kind: str,
) -> str:
    parameter_summary = parameter_name or ("fragment" if candidate_kind.startswith("hash") else "input")
    return (
        f"Attacker-controlled {parameter_summary} from {primary_source} may reach {primary_sink} on {route_group}."
    )


def _browser_route_group(target_url: str) -> str:
    parsed = urlparse(target_url)
    if parsed.fragment.startswith("/"):
        fragment = parsed.fragment.split("?", 1)[0].strip("/")
        return f"/#/{fragment}" if fragment else "/#"
    return _route_group(target_url) or "/"


def _route_group(target_url: str) -> str:
    parsed = urlparse(target_url)
    path = (parsed.path or "/").strip("/")
    segments = [segment for segment in path.split("/") if segment]
    normalized: list[str] = []
    for segment in segments:
        if segment.isdigit():
            normalized.append("{id}")
        elif re.fullmatch(r"[0-9a-f]{8,}", segment, re.IGNORECASE):
            normalized.append("{token}")
        else:
            normalized.append(segment)
    rendered = "/" + "/".join(normalized)
    return rendered if rendered != "/" else "/"


def _join_url(base_url: str, path: str) -> str:
    if not path:
        return base_url
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def _candidate_from_request_url(request_url: str) -> tuple[str, str | None]:
    parsed = urlparse(request_url)
    query = list(parse_qsl(parsed.query, keep_blank_values=True))
    if query:
        key, _ = query[0]
        return "query", key

    fragment = parsed.fragment or ""
    _, has_hash_query, fragment_query = fragment.partition("?")
    if has_hash_query:
        fragment_pairs = list(parse_qsl(fragment_query, keep_blank_values=True))
        if fragment_pairs:
            key, _ = fragment_pairs[0]
            return "hash_query", key
    if fragment:
        return "hash_fragment", None
    return "query", None


def _source_for_candidate_kind(candidate_kind: str) -> str:
    if candidate_kind == "hash_query":
        return "location.hash"
    if candidate_kind == "hash_fragment":
        return "location.hash"
    return "location.search"


def _workflow_state_for_route(
    *,
    route_group: str,
    requires_auth: bool,
    auth_states: list[str],
    candidate_kind: str,
    parameter_name: str | None,
) -> str:
    lowered_group = route_group.lower()
    if "search" in lowered_group or (parameter_name or "").strip().lower() in {"q", "query", "search"}:
        return "client_search_reflection_state"
    if any(state.strip().lower() in {"elevated", "privileged"} for state in auth_states):
        return "privileged_surface"
    if requires_auth:
        return "authenticated_surface"
    if candidate_kind.startswith("hash"):
        return "client_search_reflection_state"
    return "anonymous_surface"


def _stored_workflow_state(*, route_group: str, requires_auth: bool, auth_states: list[str]) -> str:
    lowered_group = route_group.lower()
    if "account" in lowered_group or "profile" in lowered_group:
        return "account_management_workflow"
    if "basket" in lowered_group or "checkout" in lowered_group or "cart" in lowered_group:
        return "basket_checkout_workflow"
    if any(state.strip().lower() in {"elevated", "privileged"} for state in auth_states):
        return "privileged_surface"
    if requires_auth:
        return "authenticated_surface"
    return "anonymous_surface"


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _dedupe_strings(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = str(value or "").strip()
        lowered = normalized.lower()
        if not normalized or lowered in seen:
            continue
        seen.add(lowered)
        deduped.append(normalized)
    return deduped


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _is_xss_candidate_parameter(name: str) -> bool:
    return name.strip().lower() in _XSS_PARAMETER_HINTS


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        numeric = default
    return max(minimum, min(maximum, numeric))


def _cheatsheet_entry_keys(category: dict[str, Any]) -> list[str]:
    entries = category.get("entries") or []
    if not isinstance(entries, list):
        return []
    keys: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        key = str(entry.get("key") or "").strip()
        if key:
            keys.append(key)
    return keys
