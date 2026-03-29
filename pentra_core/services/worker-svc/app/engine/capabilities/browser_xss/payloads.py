"""Safe canary payload archetypes for the Browser XSS capability pack."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import yaml

_CAPABILITY_DIR = Path(__file__).resolve().parent
_PAYLOAD_REGISTRY_PATH = _CAPABILITY_DIR / "browser_xss_payloads.yaml"

_REQUIRED_ARCHETYPE_KEYS = {
    "key",
    "title",
    "flow_modes",
    "candidate_kinds",
    "context_tags",
    "target_profile_keys",
    "browser_compatibility",
    "interaction_requirement",
    "proof_contract",
    "transport",
    "canary_template",
    "parameter_required",
    "requires_safe_replay",
    "source_keys",
    "cheatsheet_entry_keys",
}


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text()) or {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"Browser XSS payload registry must contain a YAML object: {path}")
    return payload


@lru_cache(maxsize=1)
def load_browser_xss_payload_registry() -> dict[str, Any]:
    payload = _load_yaml(_PAYLOAD_REGISTRY_PATH)
    archetypes = payload.get("payload_archetypes") or []
    if not isinstance(archetypes, list) or not archetypes:
        raise RuntimeError("Browser XSS payload registry must define payload_archetypes")

    archetypes_by_key: dict[str, dict[str, Any]] = {}
    normalized_archetypes: list[dict[str, Any]] = []
    for item in archetypes:
        if not isinstance(item, dict):
            raise RuntimeError("Browser XSS payload archetype entries must be objects")
        missing = sorted(_REQUIRED_ARCHETYPE_KEYS - set(item.keys()))
        if missing:
            raise RuntimeError(
                f"Browser XSS payload archetype {item.get('key')!r} is missing required keys: {', '.join(missing)}"
            )
        key = str(item.get("key") or "").strip()
        if not key:
            raise RuntimeError("Browser XSS payload archetype key cannot be empty")
        normalized = {
            **item,
            "key": key,
            "flow_modes": _string_list(item.get("flow_modes")),
            "candidate_kinds": _string_list(item.get("candidate_kinds")),
            "source_markers": _string_list(item.get("source_markers")),
            "sink_markers": _string_list(item.get("sink_markers")),
            "context_tags": _string_list(item.get("context_tags")),
            "target_profile_keys": _string_list(item.get("target_profile_keys")),
            "browser_compatibility": _string_list(item.get("browser_compatibility")),
            "source_keys": _string_list(item.get("source_keys")),
            "cheatsheet_entry_keys": _string_list(item.get("cheatsheet_entry_keys")),
            "parameter_required": bool(item.get("parameter_required")),
            "requires_safe_replay": bool(item.get("requires_safe_replay")),
            "interaction_requirement": str(item.get("interaction_requirement") or "none").strip(),
            "proof_contract": str(item.get("proof_contract") or "").strip(),
            "transport": str(item.get("transport") or "").strip(),
            "canary_template": str(item.get("canary_template") or "{{CANARY_MARKER}}").strip(),
        }
        archetypes_by_key[key] = normalized
        normalized_archetypes.append(normalized)

    return {
        **payload,
        "payload_archetypes": normalized_archetypes,
        "payload_archetypes_by_key": archetypes_by_key,
    }


def select_browser_xss_payload_archetype(
    *,
    flow_mode: str,
    candidate_kind: str,
    target_profile: str,
    source_markers: list[str],
    sink_markers: list[str],
    parameter_name: str | None,
    safe_replay: bool,
) -> dict[str, Any]:
    registry = load_browser_xss_payload_registry()
    best_match: dict[str, Any] | None = None
    best_score = -1

    for archetype in registry["payload_archetypes"]:
        if flow_mode not in archetype["flow_modes"]:
            continue
        if candidate_kind not in archetype["candidate_kinds"]:
            continue
        if target_profile not in archetype["target_profile_keys"]:
            continue
        if archetype["parameter_required"] and not (parameter_name or "").strip():
            continue
        if archetype["requires_safe_replay"] and not safe_replay:
            continue

        score = 0
        source_overlap = set(source_markers).intersection(archetype.get("source_markers") or [])
        sink_overlap = set(sink_markers).intersection(archetype.get("sink_markers") or [])
        score += len(source_overlap) * 3
        score += len(sink_overlap) * 2
        if parameter_name:
            score += 2
        if candidate_kind.startswith("hash") and "spa_rest_api" in archetype["target_profile_keys"]:
            score += 1
        if safe_replay and archetype["requires_safe_replay"]:
            score += 4

        if score > best_score:
            best_score = score
            best_match = {
                **archetype,
                "selector_score": score,
                "matched_source_markers": sorted(source_overlap),
                "matched_sink_markers": sorted(sink_overlap),
            }

    if best_match is None:
        raise RuntimeError(
            "No safe browser XSS payload archetype matched the candidate context "
            f"(flow_mode={flow_mode}, candidate_kind={candidate_kind}, target_profile={target_profile})"
        )
    return best_match


def build_browser_xss_payload_plan(
    *,
    archetype: dict[str, Any],
    request_url: str,
    route_group: str,
    flow_mode: str,
    candidate_kind: str,
    parameter_name: str | None,
    form_action_url: str | None = None,
    form_method: str | None = None,
    render_url: str | None = None,
    hidden_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "archetype_key": archetype["key"],
        "title": archetype["title"],
        "description": archetype.get("description"),
        "flow_mode": flow_mode,
        "candidate_kind": candidate_kind,
        "transport": archetype["transport"],
        "request_url": request_url,
        "route_group": route_group,
        "parameter_name": parameter_name,
        "canary_template": archetype["canary_template"],
        "proof_contract": archetype["proof_contract"],
        "browser_compatibility": list(archetype.get("browser_compatibility") or []),
        "interaction_requirement": archetype.get("interaction_requirement"),
        "context_tags": list(archetype.get("context_tags") or []),
        "source_keys": list(archetype.get("source_keys") or []),
        "cheatsheet_entry_keys": list(archetype.get("cheatsheet_entry_keys") or []),
        "requires_safe_replay": bool(archetype.get("requires_safe_replay")),
        "form_action_url": form_action_url,
        "form_method": form_method,
        "render_url": render_url,
        "form_hidden_fields": hidden_fields or {},
    }


def instantiate_browser_xss_canary_plan(
    *,
    payload_plan: dict[str, Any],
    canary_marker: str,
) -> dict[str, Any]:
    transport = str(payload_plan.get("transport") or "").strip()
    request_url = str(payload_plan.get("request_url") or "").strip()
    parameter_name = str(payload_plan.get("parameter_name") or "").strip() or None

    if transport == "query":
        return {
            "mode": "navigate",
            "navigate_url": _inject_query_value(request_url, parameter_name=parameter_name, payload=canary_marker),
        }
    if transport == "hash_query":
        return {
            "mode": "navigate",
            "navigate_url": _inject_hash_value(request_url, parameter_name=parameter_name, payload=canary_marker),
        }
    if transport == "hash_fragment":
        parsed = urlparse(request_url)
        return {
            "mode": "navigate",
            "navigate_url": urlunparse(parsed._replace(fragment=canary_marker)),
        }
    if transport == "stored_form":
        hidden_fields = payload_plan.get("form_hidden_fields") or {}
        if not isinstance(hidden_fields, dict):
            hidden_fields = {}
        form_payload = {str(key): str(value) for key, value in hidden_fields.items() if str(key).strip()}
        if parameter_name:
            form_payload[parameter_name] = canary_marker
        return {
            "mode": "stored_form",
            "submit_url": str(payload_plan.get("form_action_url") or request_url).strip() or request_url,
            "submit_method": str(payload_plan.get("form_method") or "POST").strip().upper(),
            "render_url": str(payload_plan.get("render_url") or request_url).strip() or request_url,
            "form_payload": form_payload,
            "parameter_name": parameter_name,
        }
    return {"mode": "navigate", "navigate_url": request_url}


def _inject_query_value(request_url: str, *, parameter_name: str | None, payload: str) -> str:
    parsed = urlparse(request_url)
    query = list(parse_qsl(parsed.query, keep_blank_values=True))
    if not query and parameter_name:
        query = [(parameter_name, payload)]
    elif query:
        key = parameter_name or query[0][0]
        replaced = False
        new_query: list[tuple[str, str]] = []
        for current_key, current_value in query:
            if not replaced and current_key == key:
                new_query.append((current_key, payload))
                replaced = True
            else:
                new_query.append((current_key, current_value))
        if not replaced:
            new_query.append((key, payload))
        query = new_query
    return urlunparse(parsed._replace(query=urlencode(query)))


def _inject_hash_value(request_url: str, *, parameter_name: str | None, payload: str) -> str:
    parsed = urlparse(request_url)
    fragment = parsed.fragment or ""
    route, _, fragment_query = fragment.partition("?")
    query = list(parse_qsl(fragment_query, keep_blank_values=True))
    if query:
        key = parameter_name or query[0][0]
        replaced = False
        rewritten: list[tuple[str, str]] = []
        for current_key, current_value in query:
            if not replaced and current_key == key:
                rewritten.append((current_key, payload))
                replaced = True
            else:
                rewritten.append((current_key, current_value))
        if not replaced:
            rewritten.append((key, payload))
        fragment = f"{route}?{urlencode(rewritten)}"
    elif parameter_name:
        fragment = f"{route}?{urlencode([(parameter_name, payload)])}"
    else:
        fragment = payload
    return urlunparse(parsed._replace(fragment=fragment))


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]
