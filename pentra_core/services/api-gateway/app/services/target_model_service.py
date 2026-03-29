"""Target-model service — derive a planner-facing target snapshot from persisted scan truth."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlparse
import re
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from pentra_common.storage.artifacts import read_json_artifact

from app.models.asset import Asset
from app.models.attack_graph import ScanArtifact
from app.models.finding import Finding
from app.models.scan import Scan

_TRUTH_STATES = ("observed", "suspected", "reproduced", "verified", "rejected", "expired")
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_SENSITIVE_PARAMETER_HINTS = (
    "password",
    "passwd",
    "token",
    "secret",
    "csrf",
    "session",
    "cookie",
    "auth",
    "otp",
    "code",
    "id",
)
_UUIDISH_SEGMENT = re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE)


async def get_scan_target_model(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> dict[str, Any] | None:
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id, Scan.tenant_id == tenant_id)
        .options(
            selectinload(Scan.asset),
            selectinload(Scan.findings),
            selectinload(Scan.artifacts),
        )
    )
    scan = (await session.execute(stmt)).scalar_one_or_none()
    if scan is None:
        return None

    artifact_entries: list[dict[str, Any]] = []
    for artifact in sorted(scan.artifacts, key=lambda item: item.created_at):
        payload = read_json_artifact(artifact.storage_ref)
        if isinstance(payload, dict):
            artifact_entries.append(
                {
                    "artifact_type": artifact.artifact_type,
                    "payload": payload,
                    "created_at": artifact.created_at,
                }
            )

    return _build_target_model_snapshot(
        scan=scan,
        findings=list(scan.findings),
        artifact_entries=artifact_entries,
    )


def _build_target_model_snapshot(
    *,
    scan: Scan | Any,
    findings: list[Finding | Any],
    artifact_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    endpoint_map: dict[str, dict[str, Any]] = {}
    entity_key_to_url: dict[str, str] = {}
    workflow_map: dict[str, dict[str, Any]] = {}
    source_artifact_types = sorted(
        {
            str(entry.get("artifact_type") or "").strip()
            for entry in artifact_entries
            if str(entry.get("artifact_type") or "").strip()
        }
    )
    seeded_route_groups = _seeded_route_groups(scan)

    for entry in artifact_entries:
        payload = entry.get("payload")
        if not isinstance(payload, dict):
            continue
        if str(entry.get("artifact_type") or payload.get("artifact_type") or "") != "endpoints":
            continue
        for item in _as_list(payload.get("items")):
            if not isinstance(item, dict):
                continue
            endpoint = _ensure_endpoint(endpoint_map, _endpoint_url_from_item(item))
            if endpoint is None:
                continue
            _merge_endpoint_item(
                endpoint,
                item,
                seeded_route_groups=seeded_route_groups,
            )
            entity_key = str(item.get("entity_key") or "").strip()
            if entity_key:
                entity_key_to_url[entity_key] = endpoint["url"]

    for finding in findings:
        _merge_finding_into_target_model(endpoint_map, finding)

    for entry in artifact_entries:
        payload = entry.get("payload")
        if not isinstance(payload, dict):
            continue
        for relationship in _as_list(payload.get("relationships")):
            if not isinstance(relationship, dict):
                continue
            source_url = entity_key_to_url.get(str(relationship.get("source_key") or "").strip())
            target_url = entity_key_to_url.get(str(relationship.get("target_key") or "").strip())
            if not source_url or not target_url:
                continue
            edge_type = str(relationship.get("edge_type") or "workflow").strip().lower()
            if edge_type in {"discovery", "exploit"}:
                continue
            workflow_key = f"{source_url}|{target_url}|{edge_type}"
            workflow = workflow_map.setdefault(
                workflow_key,
                {
                    "source_url": source_url,
                    "target_url": target_url,
                    "action": edge_type,
                    "source_route_group": endpoint_map[source_url]["route_group"],
                    "target_route_group": endpoint_map[target_url]["route_group"],
                    "requires_auth": bool(
                        endpoint_map[source_url]["requires_auth"]
                        or endpoint_map[target_url]["requires_auth"]
                    ),
                },
            )
            _merge_endpoint_origin(endpoint_map[source_url], "workflow_derived")
            _merge_endpoint_origin(endpoint_map[target_url], "workflow_derived")
            workflow["requires_auth"] = bool(
                workflow["requires_auth"]
                or endpoint_map[source_url]["requires_auth"]
                or endpoint_map[target_url]["requires_auth"]
            )

    endpoints = sorted(
        (_finalize_endpoint(item) for item in endpoint_map.values()),
        key=lambda item: (
            -_truth_pressure(item["truth_counts"]),
            -item["finding_count"],
            item["route_group"],
            item["url"],
        ),
    )
    route_groups = _build_route_groups(endpoints)
    technologies = _build_technology_index(endpoints, findings)
    parameters = _build_parameter_index(endpoints, findings)
    auth_surfaces = _build_auth_surfaces(endpoints)
    workflows = sorted(
        workflow_map.values(),
        key=lambda item: (item["source_route_group"], item["target_route_group"], item["action"]),
    )
    planner_focus = _build_planner_focus(route_groups)

    overview = {
        "endpoint_count": len(endpoints),
        "authenticated_endpoint_count": sum(1 for item in endpoints if item["requires_auth"]),
        "api_endpoint_count": sum(1 for item in endpoints if item["surface"] == "api"),
        "route_group_count": len(route_groups),
        "workflow_edge_count": len(workflows),
        "technology_count": len(technologies),
        "parameter_count": len(parameters),
        "auth_surface_count": len(auth_surfaces),
        "finding_count": sum(item["finding_count"] for item in endpoints),
        "source_artifact_types": source_artifact_types,
        "truth_counts": _aggregate_truth_counts(endpoints),
        "severity_counts": _aggregate_severity_counts(endpoints),
    }

    asset = getattr(scan, "asset", None)
    generated_at = datetime.now(timezone.utc)
    return {
        "scan_id": scan.id,
        "tenant_id": scan.tenant_id,
        "asset_id": scan.asset_id,
        "asset_name": str(getattr(asset, "name", None) or getattr(scan, "asset_id", "")),
        "target": str(getattr(asset, "target", None) or ""),
        "generated_at": generated_at,
        "overview": overview,
        "endpoints": endpoints,
        "route_groups": route_groups,
        "technologies": technologies,
        "parameters": parameters,
        "auth_surfaces": auth_surfaces,
        "workflows": workflows,
        "planner_focus": planner_focus,
    }


def _endpoint_url_from_item(item: dict[str, Any]) -> str:
    return str(item.get("url") or item.get("endpoint") or item.get("target") or "").strip()


def _ensure_endpoint(endpoint_map: dict[str, dict[str, Any]], url: str) -> dict[str, Any] | None:
    if not url or "://" not in url:
        return None
    existing = endpoint_map.get(url)
    if existing is not None:
        return existing

    path = _path_from_url(url)
    endpoint = {
        "url": url,
        "host": _host_from_url(url),
        "path": path,
        "route_group": _route_group(url),
        "surface": "api" if "/api/" in path or path.startswith("/graphql") else "web",
        "requires_auth": False,
        "auth_variants": set(),
        "methods": set(),
        "parameter_names": set(),
        "hidden_parameter_names": set(),
        "technologies": set(),
        "finding_ids": set(),
        "vulnerability_types": set(),
        "truth_counts": _truth_counts_template(),
        "severity_counts": _severity_counts_template(),
        "has_csrf": False,
        "safe_replay": False,
        "origins": set(),
    }
    for name, _value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if name:
            endpoint["parameter_names"].add(name)
    endpoint_map[url] = endpoint
    return endpoint


def _merge_endpoint_item(
    endpoint: dict[str, Any],
    item: dict[str, Any],
    *,
    seeded_route_groups: set[str],
) -> None:
    route_group = str(item.get("route_group") or "").strip()
    if route_group:
        endpoint["route_group"] = route_group

    surface = str(item.get("surface") or "").strip()
    if surface:
        endpoint["surface"] = surface

    if item.get("requires_auth"):
        endpoint["requires_auth"] = True
    if item.get("has_csrf"):
        endpoint["has_csrf"] = True
    if item.get("safe_replay"):
        endpoint["safe_replay"] = True

    method = str(item.get("http_method") or "GET").strip().upper()
    if method:
        endpoint["methods"].add(method)

    for name in _strings(item.get("auth_variants")):
        endpoint["auth_variants"].add(name)
    session_label = str(item.get("session_label") or "").strip()
    if session_label:
        endpoint["auth_variants"].add(session_label)

    for name in _strings(item.get("form_field_names")):
        endpoint["parameter_names"].add(name)
    for name in _strings(item.get("hidden_field_names")):
        endpoint["hidden_parameter_names"].add(name)

    for name, _value in parse_qsl(urlparse(endpoint["url"]).query, keep_blank_values=True):
        if name:
            endpoint["parameter_names"].add(name)

    for tech in _strings(item.get("tech_stack")):
        endpoint["technologies"].add(tech)
    primary_technology = str(item.get("primary_technology") or "").strip()
    if primary_technology:
        endpoint["technologies"].add(primary_technology)

    _merge_endpoint_origin(
        endpoint,
        _origin_for_endpoint_item(item, seeded_route_groups=seeded_route_groups),
    )


def _merge_finding_into_target_model(endpoint_map: dict[str, dict[str, Any]], finding: Finding | Any) -> None:
    evidence = _as_dict(getattr(finding, "evidence", None))
    classification = _as_dict(evidence.get("classification"))
    endpoint_url = str(evidence.get("endpoint") or evidence.get("target") or "").strip()
    route_group = str(classification.get("route_group") or "").strip()
    technology = str(classification.get("primary_technology") or "").strip()
    parameter = str(
        classification.get("parameter")
        or evidence.get("parameter")
        or ""
    ).strip()

    endpoint = _ensure_endpoint(endpoint_map, endpoint_url) if endpoint_url else None
    if endpoint is None and route_group:
        synthetic_url = f"https://target-model.local{route_group if route_group.startswith('/') else '/' + route_group}"
        endpoint = _ensure_endpoint(endpoint_map, synthetic_url)
    if endpoint is None:
        return
    _merge_endpoint_origin(endpoint, "finding_derived")

    if route_group:
        endpoint["route_group"] = route_group
    if technology:
        endpoint["technologies"].add(technology)

    vulnerability_type = str(getattr(finding, "vulnerability_type", None) or "").strip()
    if vulnerability_type:
        endpoint["vulnerability_types"].add(vulnerability_type)

    truth_state = str(getattr(finding, "truth_state", None) or "observed")
    if truth_state not in endpoint["truth_counts"]:
        truth_state = "observed"
    endpoint["truth_counts"][truth_state] += 1

    severity = str(getattr(finding, "severity", "info") or "info")
    if severity not in endpoint["severity_counts"]:
        severity = "info"
    endpoint["severity_counts"][severity] += 1

    endpoint["finding_ids"].add(str(getattr(finding, "id", "")))
    if parameter:
        endpoint["parameter_names"].add(parameter)

    if str(getattr(finding, "source_type", "")) == "exploit_verify":
        endpoint["safe_replay"] = True


def _finalize_endpoint(endpoint: dict[str, Any]) -> dict[str, Any]:
    origins = sorted(endpoint["origins"]) or ["observed"]
    return {
        "url": endpoint["url"],
        "host": endpoint["host"],
        "path": endpoint["path"],
        "route_group": endpoint["route_group"],
        "surface": endpoint["surface"],
        "requires_auth": endpoint["requires_auth"],
        "auth_variants": sorted(endpoint["auth_variants"]),
        "methods": sorted(endpoint["methods"]),
        "parameter_names": sorted(endpoint["parameter_names"]),
        "hidden_parameter_names": sorted(endpoint["hidden_parameter_names"]),
        "technologies": sorted(endpoint["technologies"]),
        "finding_count": len(endpoint["finding_ids"]),
        "vulnerability_types": sorted(endpoint["vulnerability_types"]),
        "truth_counts": dict(endpoint["truth_counts"]),
        "severity_counts": dict(endpoint["severity_counts"]),
        "has_csrf": endpoint["has_csrf"],
        "safe_replay": endpoint["safe_replay"],
        "origin": _dominant_origin(origins),
        "origins": origins,
    }


def _build_route_groups(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for endpoint in endpoints:
        group = groups.setdefault(
            endpoint["route_group"],
            {
                "route_group": endpoint["route_group"],
                "endpoint_count": 0,
                "requires_auth": False,
                "auth_variants": set(),
                "methods": set(),
                "parameter_names": set(),
                "technologies": set(),
                "finding_count": 0,
                "vulnerability_types": set(),
                "truth_counts": _truth_counts_template(),
                "severity_counts": _severity_counts_template(),
                "focus_score": 0,
                "origins": set(),
            },
        )
        group["endpoint_count"] += 1
        group["requires_auth"] = bool(group["requires_auth"] or endpoint["requires_auth"])
        group["auth_variants"].update(endpoint["auth_variants"])
        group["methods"].update(endpoint["methods"])
        group["parameter_names"].update(endpoint["parameter_names"])
        group["technologies"].update(endpoint["technologies"])
        group["finding_count"] += endpoint["finding_count"]
        group["vulnerability_types"].update(endpoint["vulnerability_types"])
        group["origins"].update(endpoint.get("origins") or [])
        for key, value in endpoint["truth_counts"].items():
            group["truth_counts"][key] += int(value or 0)
        for key, value in endpoint["severity_counts"].items():
            group["severity_counts"][key] += int(value or 0)

    finalized: list[dict[str, Any]] = []
    for item in groups.values():
        item["focus_score"] = _route_focus_score(item)
        finalized.append(
            {
                "route_group": item["route_group"],
                "endpoint_count": item["endpoint_count"],
                "requires_auth": item["requires_auth"],
                "auth_variants": sorted(item["auth_variants"]),
                "methods": sorted(item["methods"]),
                "parameter_names": sorted(item["parameter_names"]),
                "technologies": sorted(item["technologies"]),
                "finding_count": item["finding_count"],
                "vulnerability_types": sorted(item["vulnerability_types"]),
                "truth_counts": dict(item["truth_counts"]),
                "severity_counts": dict(item["severity_counts"]),
                "focus_score": item["focus_score"],
                "origin": _dominant_origin(sorted(item["origins"])),
                "origins": sorted(item["origins"]),
            }
        )
    return sorted(finalized, key=lambda item: (-item["focus_score"], item["route_group"]))


def _build_technology_index(endpoints: list[dict[str, Any]], findings: list[Finding | Any]) -> list[dict[str, Any]]:
    techs: dict[str, dict[str, Any]] = {}
    for endpoint in endpoints:
        for technology in endpoint["technologies"]:
            tech = techs.setdefault(
                technology,
                {
                    "technology": technology,
                    "endpoint_count": 0,
                    "route_groups": set(),
                    "surfaces": set(),
                },
            )
            tech["endpoint_count"] += 1
            tech["route_groups"].add(endpoint["route_group"])
            tech["surfaces"].add(endpoint["surface"])

    for finding in findings:
        evidence = _as_dict(getattr(finding, "evidence", None))
        classification = _as_dict(evidence.get("classification"))
        technology = str(classification.get("primary_technology") or "").strip()
        if not technology:
            continue
        tech = techs.setdefault(
            technology,
            {
                "technology": technology,
                "endpoint_count": 0,
                "route_groups": set(),
                "surfaces": set(),
            },
        )
        route_group = str(classification.get("route_group") or "").strip()
        if route_group:
            tech["route_groups"].add(route_group)
        surface = str(classification.get("surface") or "").strip()
        if surface:
            tech["surfaces"].add(surface)

    return sorted(
        (
            {
                "technology": item["technology"],
                "endpoint_count": item["endpoint_count"],
                "route_groups": sorted(item["route_groups"]),
                "surfaces": sorted(item["surfaces"]),
            }
            for item in techs.values()
        ),
        key=lambda item: (-item["endpoint_count"], item["technology"]),
    )


def _build_parameter_index(endpoints: list[dict[str, Any]], findings: list[Finding | Any]) -> list[dict[str, Any]]:
    params: dict[str, dict[str, Any]] = {}

    for endpoint in endpoints:
        all_params = [(name, "query_or_form") for name in endpoint["parameter_names"]]
        all_params.extend((name, "hidden_form") for name in endpoint["hidden_parameter_names"])
        for name, location in all_params:
            item = params.setdefault(
                name,
                {
                    "name": name,
                    "locations": set(),
                    "endpoints": set(),
                    "route_groups": set(),
                    "related_vulnerability_types": set(),
                    "related_truth_states": set(),
                    "likely_sensitive": _is_sensitive_parameter(name),
                },
            )
            item["locations"].add(location)
            item["endpoints"].add(endpoint["url"])
            item["route_groups"].add(endpoint["route_group"])
            item["related_vulnerability_types"].update(endpoint["vulnerability_types"])
            for state, count in endpoint["truth_counts"].items():
                if count:
                    item["related_truth_states"].add(state)

    for finding in findings:
        evidence = _as_dict(getattr(finding, "evidence", None))
        classification = _as_dict(evidence.get("classification"))
        name = str(classification.get("parameter") or evidence.get("parameter") or "").strip()
        if not name:
            continue
        item = params.setdefault(
            name,
            {
                "name": name,
                "locations": set(),
                "endpoints": set(),
                "route_groups": set(),
                "related_vulnerability_types": set(),
                "related_truth_states": set(),
                "likely_sensitive": _is_sensitive_parameter(name),
            },
        )
        item["locations"].add("finding")
        endpoint = str(evidence.get("endpoint") or "").strip()
        if endpoint:
            item["endpoints"].add(endpoint)
        route_group = str(classification.get("route_group") or "").strip()
        if route_group:
            item["route_groups"].add(route_group)
        vulnerability_type = str(getattr(finding, "vulnerability_type", None) or "").strip()
        if vulnerability_type:
            item["related_vulnerability_types"].add(vulnerability_type)
        truth_state = str(getattr(finding, "truth_state", None) or "observed")
        item["related_truth_states"].add(truth_state)

    return sorted(
        (
            {
                "name": item["name"],
                "locations": sorted(item["locations"]),
                "endpoint_count": len(item["endpoints"]),
                "route_groups": sorted(item["route_groups"]),
                "related_vulnerability_types": sorted(item["related_vulnerability_types"]),
                "related_truth_states": sorted(item["related_truth_states"]),
                "likely_sensitive": item["likely_sensitive"],
            }
            for item in params.values()
        ),
        key=lambda item: (-item["endpoint_count"], item["name"]),
    )


def _build_auth_surfaces(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    surfaces: dict[str, dict[str, Any]] = {}

    for endpoint in endpoints:
        labels = endpoint["auth_variants"] or (["authenticated"] if endpoint["requires_auth"] else ["unauthenticated"])
        for label in labels:
            auth_state = "authenticated" if label != "unauthenticated" else "none"
            surface = surfaces.setdefault(
                label,
                {
                    "label": label,
                    "auth_state": auth_state,
                    "endpoint_urls": set(),
                    "route_groups": set(),
                    "csrf_form_count": 0,
                    "safe_replay_count": 0,
                },
            )
            if endpoint["url"] not in surface["endpoint_urls"]:
                surface["endpoint_urls"].add(endpoint["url"])
                surface["route_groups"].add(endpoint["route_group"])
                if endpoint["has_csrf"]:
                    surface["csrf_form_count"] += 1
                if endpoint["safe_replay"]:
                    surface["safe_replay_count"] += 1

    return sorted(
        (
            {
                "label": item["label"],
                "auth_state": item["auth_state"],
                "endpoint_count": len(item["endpoint_urls"]),
                "route_groups": sorted(item["route_groups"]),
                "csrf_form_count": item["csrf_form_count"],
                "safe_replay_count": item["safe_replay_count"],
            }
            for item in surfaces.values()
        ),
        key=lambda item: (-item["endpoint_count"], item["label"]),
    )


def _build_planner_focus(route_groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    focus: list[dict[str, Any]] = []
    for group in route_groups:
        score = _route_focus_score(group)
        if score <= 0:
            continue
        objective = _focus_objective(group)
        reason = _focus_reason(group)
        focus.append(
            {
                "route_group": group["route_group"],
                "objective": objective,
                "reason": reason,
                "requires_auth": bool(group["requires_auth"]),
                "focus_score": score,
                "vulnerability_types": list(group["vulnerability_types"]),
                "parameter_names": list(group["parameter_names"]),
            }
        )
    return sorted(focus, key=lambda item: (-item["focus_score"], item["route_group"]))[:5]


def _focus_objective(group: dict[str, Any]) -> str:
    vulnerability_types = set(group["vulnerability_types"])
    if {"auth_bypass", "idor", "workflow_bypass"} & vulnerability_types:
        return "Deepen authorization and workflow pressure on this route group."
    if "sql_injection" in vulnerability_types:
        return "Focus parameter validation and replayable proof on this route group."
    if group["requires_auth"]:
        return "Expand authenticated route understanding and verify privileged transitions."
    return "Close evidence gaps and expand the highest-pressure route family."


def _focus_reason(group: dict[str, Any]) -> str:
    truth = group["truth_counts"]
    finding_count = int(group["finding_count"])
    parameters = len(group["parameter_names"])
    auth_text = "authenticated" if group["requires_auth"] else "public"
    return (
        f"{finding_count} findings across a {auth_text} route group with "
        f"{truth.get('verified', 0)} verified, {truth.get('reproduced', 0)} reproduced, "
        f"{truth.get('suspected', 0)} suspected, and {parameters} parameter signals."
    )


def _route_focus_score(group: dict[str, Any]) -> int:
    origins = {str(item).strip() for item in list(group.get("origins") or []) if str(item).strip()}
    if origins == {"seeded_probe"}:
        return 0
    truth = group["truth_counts"]
    severity = group["severity_counts"]
    return (
        int(truth.get("verified", 0)) * 8
        + int(truth.get("reproduced", 0)) * 6
        + int(truth.get("suspected", 0)) * 4
        + int(truth.get("observed", 0)) * 2
        + int(severity.get("critical", 0)) * 5
        + int(severity.get("high", 0)) * 3
        + int(severity.get("medium", 0)) * 2
        + min(len(group["parameter_names"]), 3)
        + (2 if group["requires_auth"] else 0)
    )


def _truth_pressure(truth_counts: dict[str, int]) -> int:
    return (
        int(truth_counts.get("verified", 0)) * 8
        + int(truth_counts.get("reproduced", 0)) * 6
        + int(truth_counts.get("suspected", 0)) * 4
        + int(truth_counts.get("observed", 0)) * 2
    )


def _aggregate_truth_counts(endpoints: list[dict[str, Any]]) -> dict[str, int]:
    counts = _truth_counts_template()
    for endpoint in endpoints:
        for key, value in endpoint["truth_counts"].items():
            counts[key] += int(value or 0)
    return counts


def _aggregate_severity_counts(endpoints: list[dict[str, Any]]) -> dict[str, int]:
    counts = _severity_counts_template()
    for endpoint in endpoints:
        for key, value in endpoint["severity_counts"].items():
            counts[key] += int(value or 0)
    return counts


def _truth_counts_template() -> dict[str, int]:
    return {key: 0 for key in _TRUTH_STATES}


def _severity_counts_template() -> dict[str, int]:
    return {key: 0 for key in _SEVERITIES}


def _host_from_url(url: str) -> str | None:
    parsed = urlparse(url)
    return parsed.netloc or None


def _path_from_url(url: str) -> str:
    path = urlparse(url).path or "/"
    return path if path.startswith("/") else f"/{path}"


def _route_group(url: str) -> str:
    path = _path_from_url(url)
    segments = []
    for segment in path.split("/"):
        if not segment:
            continue
        if segment.isdigit() or _UUIDISH_SEGMENT.match(segment):
            segments.append("{id}")
        else:
            segments.append(segment)
    return "/" + "/".join(segments) if segments else "/"


def _is_sensitive_parameter(name: str) -> bool:
    lowered = name.strip().lower()
    return any(hint in lowered for hint in _SENSITIVE_PARAMETER_HINTS)


def _strings(value: Any) -> list[str]:
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


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _merge_endpoint_origin(endpoint: dict[str, Any], origin: str) -> None:
    text = str(origin or "").strip()
    if not text:
        return
    endpoint.setdefault("origins", set()).add(text)


def _dominant_origin(origins: list[str]) -> str:
    priority = ["observed", "finding_derived", "workflow_derived", "seeded_probe"]
    normalized = [str(item).strip() for item in origins if str(item).strip()]
    if not normalized:
        return "observed"
    for candidate in priority:
        if candidate in normalized:
            return candidate
    return normalized[0]


def _origin_for_endpoint_item(item: dict[str, Any], *, seeded_route_groups: set[str]) -> str:
    interaction_kind = str(item.get("interaction_kind") or "").strip().lower()
    route_group = str(item.get("route_group") or "").strip()
    path = _path_from_url(str(item.get("url") or item.get("endpoint") or item.get("target") or "").strip())
    if "candidate" in interaction_kind or interaction_kind in {"probe_finding"}:
        return "finding_derived"
    if interaction_kind in {"page", "form"}:
        return "observed"
    if str(item.get("discovered_from") or "").strip():
        return "observed"
    if route_group in seeded_route_groups or path in seeded_route_groups:
        return "seeded_probe"
    return "observed"


def _seeded_route_groups(scan: Scan | Any) -> set[str]:
    config = getattr(scan, "config", None)
    if not isinstance(config, dict):
        return {"/"}

    profile = config.get("profile") if isinstance(config.get("profile"), dict) else {}
    selected_checks = (
        profile.get("selected_checks")
        if isinstance(profile.get("selected_checks"), dict)
        else {}
    )
    execution_contract = (
        config.get("execution_contract")
        if isinstance(config.get("execution_contract"), dict)
        else {}
    )
    seed_candidates: list[str] = []
    for key in ("seed_paths", "http_probe_paths", "content_paths"):
        seed_candidates.extend(_strings(selected_checks.get(key)))
        seed_candidates.extend(_strings(execution_contract.get(key)))

    normalized: set[str] = {"/"}
    for candidate in seed_candidates:
        if not candidate:
            continue
        if "://" in candidate:
            normalized.add(_path_from_url(candidate))
            continue
        text = candidate if candidate.startswith("/") else f"/{candidate}"
        normalized.add(text)
    return normalized
