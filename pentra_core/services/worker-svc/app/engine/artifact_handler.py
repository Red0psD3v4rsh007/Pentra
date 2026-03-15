"""Artifact handler — normalizes raw tool output into a canonical schema."""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from pentra_common.storage.artifacts import sha256_json

logger = logging.getLogger(__name__)

# Where normalized artifacts are stored (local fs or S3-compatible path)
ARTIFACT_STORE = os.getenv("ARTIFACT_STORE_PATH", "/tmp/pentra/artifacts")
ARTIFACT_SCHEMA_VERSION = "2026-03-14"

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_VULNERABILITY_ARTIFACT_TYPES = {"vulnerabilities", "findings_scored"}
_IMPACT_ARTIFACT_TYPES = {
    "access_levels",
    "database_access",
    "shell_access",
    "credential_leak",
    "privilege_escalation",
    "verified_impact",
}


def normalize_output(
    *,
    output_dir: str,
    output_parser: str,
    tool_name: str,
    artifact_type: str,
    scan_id: str,
    node_id: str,
    tenant_id: str,
    exit_code: int,
    duration_ms: int = 0,
    scan_config: dict[str, Any] | None = None,
    execution_mode: str = "controlled_live_local",
    execution_provenance: str = "live",
    execution_reason: str | None = None,
) -> dict[str, Any]:
    """Read raw tool output and normalize it into Pentra's canonical artifact."""
    raw_items = _parse_output(output_dir, output_parser)
    raw_size = _get_output_size(output_dir)
    stateful_context = _extract_stateful_context(raw_items)

    items = _canonicalize_items(
        tool_name=tool_name,
        artifact_type=artifact_type,
        raw_items=raw_items,
    )
    items, guardrail_stats = _apply_scope_guardrails(
        artifact_type=artifact_type,
        items=items,
        scan_config=scan_config or {},
    )
    findings = _extract_findings(
        tool_name=tool_name,
        artifact_type=artifact_type,
        items=items,
    )
    evidence = _extract_evidence(
        tool_name=tool_name,
        artifact_type=artifact_type,
        findings=findings,
    )
    _apply_execution_provenance(
        findings=findings,
        evidence=evidence,
        execution_mode=execution_mode,
        execution_provenance=execution_provenance,
        execution_reason=execution_reason,
    )
    relationships = _extract_relationships(
        artifact_type=artifact_type,
        items=items,
        findings=findings,
        raw_items=raw_items,
    )
    summary = _build_summary(
        tool_name=tool_name,
        artifact_type=artifact_type,
        items=items,
        findings=findings,
        evidence=evidence,
        guardrail_stats=guardrail_stats,
        scan_config=scan_config or {},
        raw_items=raw_items,
        stateful_context=stateful_context,
    )
    summary["execution"] = {
        "mode": execution_mode,
        "provenance": execution_provenance,
        "reason": execution_reason,
    }

    artifact = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "tool": tool_name,
        "artifact_type": artifact_type,
        "scan_id": scan_id,
        "node_id": node_id,
        "tenant_id": tenant_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "item_count": len(items),
        "items": items,
        "findings": findings,
        "evidence": evidence,
        "relationships": relationships,
        "summary": summary,
        "metadata": {
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "raw_size_bytes": raw_size,
            "output_parser": output_parser,
            "content_type": "application/json",
            "guardrail_stats": guardrail_stats,
            "stateful_context": stateful_context,
            "execution_mode": execution_mode,
            "execution_provenance": execution_provenance,
            "execution_reason": execution_reason,
        },
    }

    artifact["metadata"]["checksum"] = sha256_json(
        {
            "tool": tool_name,
            "artifact_type": artifact_type,
            "scan_id": scan_id,
            "node_id": node_id,
            "item_count": artifact["item_count"],
            "items": items,
            "findings": findings,
            "relationships": relationships,
            "summary": summary,
        }
    )
    artifact["metadata"]["normalized_size_bytes"] = len(
        json.dumps(artifact, default=str).encode("utf-8")
    )

    return artifact


def build_execution_status_artifact(
    *,
    tool_name: str,
    artifact_type: str,
    scan_id: str,
    node_id: str,
    tenant_id: str,
    exit_code: int,
    duration_ms: int = 0,
    execution_mode: str,
    execution_provenance: str,
    execution_reason: str | None = None,
) -> dict[str, Any]:
    """Create a canonical artifact for blocked or non-executed runtime outcomes."""
    summary = {
        "status": execution_provenance,
        "message": _execution_status_message(
            tool_name=tool_name,
            execution_provenance=execution_provenance,
            execution_reason=execution_reason,
        ),
        "execution": {
            "mode": execution_mode,
            "provenance": execution_provenance,
            "reason": execution_reason,
        },
    }
    artifact = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "tool": tool_name,
        "artifact_type": artifact_type,
        "scan_id": scan_id,
        "node_id": node_id,
        "tenant_id": tenant_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "item_count": 0,
        "items": [],
        "findings": [],
        "evidence": [],
        "relationships": [],
        "summary": summary,
        "metadata": {
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "raw_size_bytes": 0,
            "output_parser": "runtime_status",
            "content_type": "application/json",
            "guardrail_stats": {},
            "stateful_context": {},
            "execution_mode": execution_mode,
            "execution_provenance": execution_provenance,
            "execution_reason": execution_reason,
        },
    }
    artifact["metadata"]["checksum"] = sha256_json(
        {
            "tool": tool_name,
            "artifact_type": artifact_type,
            "scan_id": scan_id,
            "node_id": node_id,
            "summary": summary,
        }
    )
    artifact["metadata"]["normalized_size_bytes"] = len(
        json.dumps(artifact, default=str).encode("utf-8")
    )
    return artifact


def store_artifact(
    artifact: dict[str, Any],
    *,
    scan_id: str,
    node_id: str,
    tenant_id: str,
    tool_name: str,
) -> str:
    """Store a normalized artifact and return its storage reference."""
    rel_path = f"{tenant_id}/{scan_id}/{node_id}/{tool_name}.json"
    full_path = Path(ARTIFACT_STORE) / rel_path
    full_path.parent.mkdir(parents=True, exist_ok=True)
    full_path.write_text(json.dumps(artifact, indent=2, default=str))

    storage_ref = f"artifacts/{rel_path}"
    logger.info(
        "Artifact stored: %s (%d items, %d findings, %d bytes)",
        storage_ref,
        artifact.get("item_count", 0),
        len(artifact.get("findings", [])),
        artifact.get("metadata", {}).get("normalized_size_bytes", 0),
    )
    return storage_ref


def _apply_execution_provenance(
    *,
    findings: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    execution_mode: str,
    execution_provenance: str,
    execution_reason: str | None,
) -> None:
    for finding in findings:
        evidence_payload = finding.get("evidence") or {}
        if not isinstance(evidence_payload, dict):
            evidence_payload = {}
        classification = evidence_payload.get("classification") or {}
        if not isinstance(classification, dict):
            classification = {}
        classification["execution_mode"] = execution_mode
        classification["execution_provenance"] = execution_provenance
        if execution_reason:
            classification["execution_reason"] = execution_reason
        evidence_payload["classification"] = classification

        metadata = evidence_payload.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}
        metadata["execution_mode"] = execution_mode
        metadata["execution_provenance"] = execution_provenance
        if execution_reason:
            metadata["execution_reason"] = execution_reason
        evidence_payload["metadata"] = metadata
        finding["evidence"] = evidence_payload

    for evidence_item in evidence:
        evidence_item["execution_mode"] = execution_mode
        evidence_item["execution_provenance"] = execution_provenance
        if execution_reason:
            evidence_item["execution_reason"] = execution_reason


def _execution_status_message(
    *,
    tool_name: str,
    execution_provenance: str,
    execution_reason: str | None,
) -> str:
    if execution_provenance == "blocked":
        if execution_reason == "not_supported":
            return f"{tool_name} is not supported in the selected live mode."
        if execution_reason == "target_policy_blocked":
            return f"{tool_name} was blocked by the selected live target policy."
    if execution_provenance == "simulated":
        return f"{tool_name} ran in explicit demo simulation mode."
    return f"{tool_name} executed with provenance {execution_provenance}."


def _canonicalize_items(
    *,
    tool_name: str,
    artifact_type: str,
    raw_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if tool_name == "web_interact":
        return _canonicalize_stateful_endpoints(raw_items)

    if artifact_type == "services":
        return _canonicalize_services(raw_items)

    if artifact_type == "endpoints":
        return _canonicalize_endpoints(raw_items)

    if artifact_type in _VULNERABILITY_ARTIFACT_TYPES:
        return _canonicalize_vulnerabilities(tool_name, raw_items)

    if artifact_type in _IMPACT_ARTIFACT_TYPES:
        return _canonicalize_impacts(tool_name, artifact_type, raw_items)

    if artifact_type == "scope":
        return _canonicalize_scope(raw_items)

    if artifact_type in {"subdomains", "hosts"}:
        return _canonicalize_assets(raw_items)

    if artifact_type == "report":
        return _canonicalize_report(raw_items)

    return raw_items


def _canonicalize_scope(raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for item in raw_items:
        target = str(item.get("target", item.get("host", item.get("domain", "unknown"))))
        scope_item = {
            "target": target,
            "asset_type": item.get("asset_type", "web_app"),
            "in_scope": bool(item.get("in_scope", True)),
            "entity_key": _entity_key("asset", target),
        }
        items.append(scope_item)
    return items


def _canonicalize_assets(raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items_by_host: dict[str, dict[str, Any]] = {}
    for item in raw_items:
        host = str(item.get("host", item.get("target", item.get("name", "unknown"))))
        asset = {
            **item,
            "host": host,
            "entity_key": _entity_key("asset", host),
        }
        items_by_host.setdefault(host.lower(), asset)
    return _sort_items(list(items_by_host.values()))


def _canonicalize_services(raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    services: dict[str, dict[str, Any]] = {}
    for item in raw_items:
        host = str(item.get("host", item.get("target", "unknown")))
        ports = item.get("ports", [])
        if not isinstance(ports, list):
            ports = []

        for port_info in ports:
            if str(port_info.get("state", "")).lower() not in {"open", "up", ""}:
                continue

            port = int(port_info.get("port", 0))
            service_item = {
                "host": host,
                "port": port,
                "protocol": port_info.get("protocol", "tcp"),
                "service": port_info.get("service") or f"tcp/{port}",
                "version": port_info.get("version") or "",
                "internet_exposed": True,
                "entity_key": _entity_key("service", f"{host}:{port}"),
            }
            services[f"{host.lower()}:{port}"] = service_item
    return _sort_items(list(services.values()))


def _canonicalize_endpoints(raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    endpoints: dict[str, dict[str, Any]] = {}
    for item in raw_items:
        nested = item.get("results")
        if isinstance(nested, list):
            for endpoint in _canonicalize_endpoints(nested):
                endpoints[endpoint["url"].lower()] = endpoint
            continue

        url = str(
            item.get("url")
            or item.get("matched-at")
            or item.get("endpoint")
            or item.get("target")
            or ""
        ).strip()
        if not url:
            continue

        host = _host_from_url(url)
        technologies = _normalize_technologies(
            item.get("technologies")
            or item.get("tech")
            or item.get("tech_stack")
            or item.get("technology")
        )
        primary_technology = technologies[0] if technologies else ""
        surface = _classify_surface(url, item)
        endpoint = {
            "url": url,
            "host": host,
            "scheme": "https" if url.startswith("https://") else "http",
            "path": _path_from_url(url),
            "status_code": int(item.get("status_code", item.get("status", 0) or 0)),
            "content_length": int(item.get("content_length", item.get("length", 0) or 0)),
            "words": int(item.get("words", 0) or 0),
            "title": str(item.get("title") or ""),
            "webserver": str(item.get("webserver") or item.get("server") or ""),
            "primary_technology": primary_technology,
            "tech_stack": technologies,
            "surface": surface,
            "is_api": surface == "api",
            "route_group": _route_group(url),
            "entity_key": _entity_key("endpoint", url),
        }
        endpoints[url.lower()] = endpoint
    return _sort_items(list(endpoints.values()))


def _canonicalize_stateful_endpoints(raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    endpoints: dict[str, dict[str, Any]] = {}

    for container in raw_items:
        pages = container.get("pages")
        if isinstance(pages, list):
            for page in pages:
                url = str(page.get("url") or "").strip()
                if not url:
                    continue
                key = url.lower()
                item = {
                    "url": url,
                    "host": _host_from_url(url),
                    "scheme": "https" if url.startswith("https://") else "http",
                    "path": _path_from_url(url),
                    "status_code": int(page.get("status_code", 0) or 0),
                    "content_length": int(page.get("content_length", 0) or 0),
                    "words": int(page.get("words", 0) or 0),
                    "title": str(page.get("title") or ""),
                    "webserver": str(page.get("webserver") or ""),
                    "primary_technology": str(page.get("primary_technology") or ""),
                    "tech_stack": _normalize_technologies(page.get("tech_stack") or page.get("technologies")),
                    "surface": str(page.get("surface") or _classify_surface(url, page)),
                    "is_api": _classify_surface(url, page) == "api",
                    "route_group": _route_group(url),
                    "entity_key": _entity_key("endpoint", url),
                    "requires_auth": bool(page.get("requires_auth", False)),
                    "session_label": str(page.get("session_label") or "unauthenticated"),
                    "auth_state": str(page.get("auth_state") or "none"),
                    "discovered_from": page.get("source_url"),
                    "interaction_kind": "page",
                }
                endpoints[key] = _merge_stateful_endpoint_item(endpoints.get(key), item)

        forms = container.get("forms")
        if isinstance(forms, list):
            for form in forms:
                action_url = str(form.get("action_url") or "").strip()
                if not action_url:
                    continue
                key = action_url.lower()
                item = {
                    "url": action_url,
                    "host": _host_from_url(action_url),
                    "scheme": "https" if action_url.startswith("https://") else "http",
                    "path": _path_from_url(action_url),
                    "status_code": 200,
                    "content_length": 0,
                    "words": 0,
                    "title": f"Form action {form.get('method', 'GET').upper()}",
                    "webserver": "",
                    "primary_technology": "",
                    "tech_stack": [],
                    "surface": "web",
                    "is_api": False,
                    "route_group": _route_group(action_url),
                    "entity_key": _entity_key("endpoint", action_url),
                    "requires_auth": bool(form.get("requires_auth", False)),
                    "session_label": str(form.get("session_label") or "unauthenticated"),
                    "auth_state": "authenticated" if form.get("requires_auth") else "none",
                    "discovered_from": form.get("page_url"),
                    "interaction_kind": "form",
                    "http_method": str(form.get("method") or "GET").upper(),
                    "form_field_names": form.get("field_names") or [],
                    "hidden_field_names": form.get("hidden_field_names") or [],
                    "has_csrf": bool(form.get("has_csrf", False)),
                    "safe_replay": bool(form.get("safe_replay", False)),
                }
                endpoints[key] = _merge_stateful_endpoint_item(endpoints.get(key), item)

    return _sort_items(list(endpoints.values()))


def _merge_stateful_endpoint_item(
    existing: dict[str, Any] | None,
    item: dict[str, Any],
) -> dict[str, Any]:
    if existing is None:
        merged = dict(item)
        merged["auth_variants"] = [item.get("session_label")] if item.get("session_label") else []
        return merged

    merged = dict(existing)
    if not merged.get("title") and item.get("title"):
        merged["title"] = item["title"]
    merged["status_code"] = max(int(merged.get("status_code", 0) or 0), int(item.get("status_code", 0) or 0))
    merged["content_length"] = max(
        int(merged.get("content_length", 0) or 0),
        int(item.get("content_length", 0) or 0),
    )
    if item.get("requires_auth"):
        merged["requires_auth"] = True
    if item.get("has_csrf"):
        merged["has_csrf"] = True
    if item.get("safe_replay"):
        merged["safe_replay"] = True
    auth_variants = set(existing.get("auth_variants") or [])
    if item.get("session_label"):
        auth_variants.add(str(item["session_label"]))
    merged["auth_variants"] = sorted(auth_variants)
    if item.get("interaction_kind") == "form":
        merged["interaction_kind"] = "form"
        merged["http_method"] = item.get("http_method") or merged.get("http_method")
        merged["form_field_names"] = sorted(
            {
                *[str(value) for value in existing.get("form_field_names", [])],
                *[str(value) for value in item.get("form_field_names", [])],
            }
        )
        merged["hidden_field_names"] = sorted(
            {
                *[str(value) for value in existing.get("hidden_field_names", [])],
                *[str(value) for value in item.get("hidden_field_names", [])],
            }
        )
    return merged


def _canonicalize_vulnerabilities(
    tool_name: str,
    raw_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if tool_name.startswith("sqlmap"):
        return _canonicalize_sqlmap_findings(raw_items)

    items: dict[str, dict[str, Any]] = {}
    for item in raw_items:
        if tool_name == "zap" and isinstance(item.get("alerts"), list):
            for nested in _canonicalize_vulnerabilities(tool_name, item["alerts"]):
                items[str(nested["finding_key"])] = nested
            continue

        severity = _normalize_severity(
            item.get("severity")
            or item.get("info", {}).get("severity")
            or item.get("risk")
        )
        target = str(
            item.get("matched-at")
            or item.get("url")
            or item.get("uri")
            or item.get("endpoint")
            or item.get("target")
            or item.get("host")
            or "unknown"
        )
        title = str(
            item.get("title")
            or item.get("name")
            or item.get("alert")
            or item.get("info", {}).get("name")
            or item.get("template-id")
            or f"{tool_name} finding"
        )
        description = (
            item.get("description")
            or item.get("desc")
            or item.get("info", {}).get("description")
            or ""
        )
        remediation = (
            item.get("remediation")
            or item.get("solution")
            or item.get("info", {}).get("remediation")
        )
        request = item.get("request")
        response = item.get("response")
        payload = item.get("payload")
        exploit_result = item.get("exploit_result")
        cve_values = _normalize_cve_values(item.get("cve") or item.get("cve_id") or item.get("info", {}).get("classification", {}).get("cve-id"))
        cvss_score = _normalize_cvss_score(
            item.get("cvss_score")
            or item.get("cvss")
            or item.get("info", {}).get("classification", {}).get("cvss-score")
        )
        confidence = _normalize_confidence(item.get("confidence"), severity)
        target_host = _host_from_url(target)
        vulnerability_type = str(
            item.get("vulnerability_type")
            or _classify_finding_family(
                title=title,
                description=description,
                tool_name=tool_name,
                target=target,
                payload=payload,
            )
        ).strip().lower()
        route_group = _route_group(target)
        exploitability = _classify_exploitability(
            title=title,
            severity=severity,
            confidence=confidence,
            tool_name=tool_name,
            payload=payload,
            exploit_result=exploit_result,
        )
        finding_key = _finding_key(
            vulnerability_type,
            target_host or target,
            route_group or target,
            cve_values[0] if cve_values else "",
        )

        vuln_item = {
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "target": target_host or target,
            "endpoint": target if "://" in target or target.startswith("/") else None,
            "description": description,
            "remediation": remediation,
            "tool_source": tool_name,
            "vulnerability_type": vulnerability_type,
            "cve_id": cve_values[0] if cve_values else None,
            "cve_ids": cve_values,
            "cvss_score": cvss_score,
            "request": request,
            "response": response,
            "payload": payload,
            "exploit_result": exploit_result,
            "references": item.get("reference") or item.get("references") or [],
            "surface": _classify_surface(target, item),
            "route_group": route_group,
            "primary_technology": _infer_primary_technology(item, target),
            "exploitability": exploitability,
            "exploitability_score": _exploitability_score(exploitability),
            "finding_key": finding_key,
        }
        items[finding_key] = _merge_vulnerability_items(items.get(finding_key), vuln_item)
    return _sort_items(list(items.values()))


def _canonicalize_sqlmap_findings(raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not raw_items:
        return []

    merged: dict[str, Any] = {
        "request_url": "",
        "target_url": "",
        "method": "",
        "parameter": "",
        "techniques": [],
        "titles": [],
        "payloads": [],
        "dbms": "",
    }
    raw_snippets: list[str] = []

    for item in raw_items:
        content = str(item.get("content") or "").strip()
        if not content:
            continue

        raw_snippets.append(content)
        relative_path = str(item.get("path") or item.get("filename") or "").lower()
        filename = str(item.get("filename") or "").lower()

        if relative_path.endswith("target.txt") or filename == "target.txt":
            target_url, method = _parse_sqlmap_target_descriptor(content)
            if target_url:
                merged["request_url"] = target_url
                merged["target_url"] = _strip_query_fragment(target_url)
            if method:
                merged["method"] = method
            continue

        if relative_path.endswith("/log") or filename == "log" or "sqlmap identified" in content.lower():
            _merge_sqlmap_log_details(merged, content)
            continue

        if _looks_like_sqlmap_results_table(content):
            _merge_sqlmap_csv_details(merged, content)
            continue

        if not merged["target_url"]:
            fallback_url = _first_url(content)
            if fallback_url:
                merged["request_url"] = fallback_url
                merged["target_url"] = _strip_query_fragment(fallback_url)

    request_url = str(merged.get("request_url") or _first_url("\n".join(raw_snippets)) or "")
    target_url = str(merged.get("target_url") or _strip_query_fragment(request_url))
    endpoint = target_url
    target = _host_from_url(endpoint or target_url) or endpoint or "sqlmap-target"
    route_group = _route_group(endpoint or target_url)
    method = str(merged.get("method") or "GET").upper()
    parameter = str(merged.get("parameter") or "").strip()
    techniques = _dedupe_strings(merged.get("techniques") or [])
    titles = _dedupe_strings(merged.get("titles") or [])
    payloads = _dedupe_strings(merged.get("payloads") or [])
    dbms = str(merged.get("dbms") or "").strip()

    description_parts: list[str] = []
    if parameter and endpoint:
        description_parts.append(
            f"sqlmap confirmed injectable parameter '{parameter}' via {method} on {endpoint}."
        )
    elif endpoint:
        description_parts.append(f"sqlmap confirmed SQL injection on {endpoint}.")

    if techniques:
        description_parts.append(f"Techniques: {', '.join(techniques)}.")
    if titles:
        description_parts.append(f"Detection details: {'; '.join(titles[:3])}.")
    if dbms:
        description_parts.append(f"Backend DBMS: {dbms}.")

    description = " ".join(description_parts).strip()
    if not description:
        description = "\n\n".join(raw_snippets)[:1000] or "sqlmap reported injectable parameters."

    request = f"{method} {request_url}" if request_url else None
    payload = payloads[0] if payloads else _extract_payload("\n".join(raw_snippets))

    exploit_result_parts: list[str] = []
    if parameter:
        exploit_result_parts.append(f"Injectable parameter: {parameter}")
    if techniques:
        exploit_result_parts.append(f"Techniques: {', '.join(techniques)}")
    if dbms:
        exploit_result_parts.append(f"DBMS: {dbms}")
    exploit_result = " | ".join(exploit_result_parts) or None

    reference_lines: list[str] = []
    if len(payloads) > 1:
        reference_lines.append(f"Additional payloads: {' | '.join(payloads[1:3])}")
    if titles:
        reference_lines.append(f"Technique titles: {' | '.join(titles[:3])}")

    primary_technology = dbms or _infer_primary_technology({"description": description}, endpoint or target_url)
    finding_route = route_group or endpoint or target
    finding_key = _finding_key("sql_injection", target, finding_route, "")

    return [
        {
            "title": "SQL Injection confirmed via sqlmap",
            "severity": "critical",
            "confidence": 95,
            "target": target,
            "endpoint": endpoint or target_url or target,
            "description": description,
            "remediation": "Use parameterized queries and server-side input validation.",
            "tool_source": "sqlmap",
            "vulnerability_type": "sql_injection",
            "cve_id": None,
            "cve_ids": [],
            "cvss_score": 9.8,
            "content": "\n\n".join(raw_snippets)[:4000],
            "payload": payload,
            "request": request,
            "response": None,
            "exploit_result": exploit_result,
            "references": reference_lines,
            "surface": _classify_surface(endpoint or target_url or target, {}),
            "route_group": route_group,
            "primary_technology": primary_technology,
            "exploitability": "high",
            "exploitability_score": 95,
            "finding_key": finding_key,
        }
    ]


def _parse_sqlmap_target_descriptor(content: str) -> tuple[str, str]:
    match = re.search(
        r"(?P<url>https?://\S+?)(?:\s+\((?P<method>[A-Z]+)\))?(?:\s+#|\s*$)",
        content,
    )
    if not match:
        return "", ""
    return match.group("url"), str(match.group("method") or "").upper()


def _merge_sqlmap_log_details(merged: dict[str, Any], content: str) -> None:
    if not merged.get("target_url"):
        target_url = _first_url(content)
        if target_url:
            merged["request_url"] = target_url
            merged["target_url"] = _strip_query_fragment(target_url)

    parameter_match = re.search(r"Parameter:\s*(?P<parameter>[^\s]+)\s*\((?P<method>[A-Z]+)\)", content)
    if parameter_match:
        merged["parameter"] = parameter_match.group("parameter")
        merged["method"] = parameter_match.group("method").upper()

    for technique in re.findall(r"^\s*Type:\s*(.+)$", content, re.MULTILINE):
        merged.setdefault("techniques", []).append(technique.strip())
    for title in re.findall(r"^\s*Title:\s*(.+)$", content, re.MULTILINE):
        merged.setdefault("titles", []).append(title.strip())
    for payload in re.findall(r"^\s*Payload:\s*(.+)$", content, re.MULTILINE):
        merged.setdefault("payloads", []).append(payload.strip())

    dbms_match = re.search(r"back-end DBMS:\s*(.+)$", content, re.IGNORECASE | re.MULTILINE)
    if dbms_match:
        merged["dbms"] = dbms_match.group(1).strip()


def _looks_like_sqlmap_results_table(content: str) -> bool:
    header = content.strip().splitlines()[:1]
    if not header:
        return False
    return header[0].lower().startswith("target url,place,parameter")


def _merge_sqlmap_csv_details(merged: dict[str, Any], content: str) -> None:
    import csv
    import io

    reader = csv.DictReader(io.StringIO(content))
    for row in reader:
        target_url = str(row.get("Target URL") or "").strip()
        if target_url and not merged.get("target_url"):
            merged["request_url"] = target_url
            merged["target_url"] = _strip_query_fragment(target_url)

        place = str(row.get("Place") or "").strip().upper()
        if place and not merged.get("method"):
            merged["method"] = place

        parameter = str(row.get("Parameter") or "").strip()
        if parameter and not merged.get("parameter"):
            merged["parameter"] = parameter

        techniques = _decode_sqlmap_techniques(str(row.get("Technique(s)") or ""))
        merged.setdefault("techniques", []).extend(techniques)

        notes = str(row.get("Note(s)") or "").strip()
        if notes:
            merged.setdefault("titles", []).append(notes)


def _decode_sqlmap_techniques(value: str) -> list[str]:
    shorthand = {
        "B": "boolean-based blind",
        "E": "error-based",
        "Q": "inline query",
        "S": "stacked queries",
        "T": "time-based blind",
        "U": "UNION query",
    }
    if not value:
        return []
    expanded = [shorthand.get(char, char) for char in value.strip() if char.strip()]
    return _dedupe_strings(expanded)


def _dedupe_strings(values: list[Any]) -> list[str]:
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


def _canonicalize_impacts(
    tool_name: str,
    artifact_type: str,
    raw_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if tool_name == "sqlmap_verify":
        return _canonicalize_sqlmap_verified_impacts(raw_items)

    items: dict[str, dict[str, Any]] = {}
    for item in raw_items:
        target = str(item.get("target", item.get("host", item.get("url", "unknown"))))
        access_level = str(
            item.get("access_level")
            or item.get("privilege")
            or item.get("role")
            or item.get("username")
            or artifact_type
        )
        evidence = item.get("exploit_result") or item.get("content") or item.get("response")
        impact_item = {
            "target": target,
            "access_level": access_level,
            "title": item.get("title") or _impact_title(artifact_type, access_level),
            "severity": _normalize_severity(item.get("severity") or "critical"),
            "confidence": _normalize_confidence(item.get("confidence"), "critical"),
            "description": item.get("description")
            or f"{tool_name} demonstrated {artifact_type.replace('_', ' ')} on {target}.",
            "tool_source": tool_name,
            "exploit_result": evidence,
            "payload": item.get("payload"),
            "request": item.get("request"),
            "response": item.get("response"),
            "account": item.get("username") or item.get("account"),
            "surface": item.get("surface") or _classify_surface(target, item),
            "route_group": item.get("route_group") or _route_group(target),
            "vulnerability_type": item.get("vulnerability_type"),
            "primary_technology": item.get("primary_technology") or _infer_primary_technology(item, target),
            "exploitability": item.get("exploitability") or "high",
            "exploitability_score": item.get("exploitability_score") or 95,
            "entity_key": _entity_key("privilege", f"{target}:{access_level}"),
        }
        items[f"{target.lower()}:{access_level.lower()}"] = impact_item
    return _sort_items(list(items.values()))


def _canonicalize_sqlmap_verified_impacts(raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = _canonicalize_sqlmap_findings(raw_items)
    if not findings:
        return []

    finding = findings[0]
    endpoint = str(finding.get("endpoint") or finding.get("target") or "unknown")
    return [
        {
            "target": endpoint,
            "access_level": "database_read",
            "title": "Verified database access via SQL injection",
            "severity": "critical",
            "confidence": 97,
            "description": (
                "Safe exploit verification confirmed database-readable SQL injection "
                f"on {endpoint}."
            ),
            "tool_source": "sqlmap_verify",
            "exploit_result": finding.get("exploit_result")
            or "Database access verified by non-destructive SQL injection confirmation.",
            "payload": finding.get("payload"),
            "request": finding.get("request"),
            "response": finding.get("response"),
            "account": finding.get("primary_technology") or "database",
            "surface": finding.get("surface"),
            "route_group": finding.get("route_group"),
            "vulnerability_type": "sql_injection",
            "primary_technology": finding.get("primary_technology"),
            "exploitability": "high",
            "exploitability_score": 98,
            "entity_key": _entity_key("privilege", f"{endpoint}:database_read"),
        }
    ]


def _canonicalize_report(raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(raw_items) == 1 and isinstance(raw_items[0], dict):
        return [raw_items[0]]
    return raw_items


def _extract_findings(
    *,
    tool_name: str,
    artifact_type: str,
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if artifact_type not in _VULNERABILITY_ARTIFACT_TYPES | _IMPACT_ARTIFACT_TYPES:
        return findings

    source_type = "scanner"
    if artifact_type == "findings_scored":
        source_type = "ai_analysis"
    elif artifact_type in _IMPACT_ARTIFACT_TYPES:
        source_type = "exploit_verify"
    verification_state = _verification_state_for_source(source_type)

    for item in items:
        title = str(item.get("title") or item.get("name") or f"{tool_name} finding")
        severity = _normalize_severity(item.get("severity"))
        target = str(item.get("target") or item.get("endpoint") or "unknown")
        endpoint = item.get("endpoint")
        cve_id = item.get("cve_id")
        confidence = int(item.get("confidence") or _normalize_confidence(None, severity))
        fingerprint = sha256_json(
            {
                "family": item.get("vulnerability_type") or item.get("title") or title,
                "target": target,
                "endpoint": item.get("route_group") or endpoint,
                "cve_id": cve_id,
                "source_type": source_type,
            }
        )
        evidence = {
            "target": target,
            "endpoint": endpoint,
            "request": item.get("request"),
            "response": item.get("response"),
            "payload": item.get("payload"),
            "exploit_result": item.get("exploit_result"),
            "references": item.get("references") or [],
            "account": item.get("account"),
            "classification": {
                "surface": item.get("surface"),
                "vulnerability_type": item.get("vulnerability_type"),
                "route_group": item.get("route_group"),
                "primary_technology": item.get("primary_technology"),
                "exploitability": item.get("exploitability"),
                "exploitability_score": item.get("exploitability_score"),
                "verification_state": verification_state,
                "verification_confidence": confidence,
                "verified": verification_state == "verified",
            },
        }
        findings.append(
            {
                "fingerprint": fingerprint,
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "target": target,
                "endpoint": endpoint,
                "description": item.get("description"),
                "remediation": item.get("remediation"),
                "tool_source": str(item.get("tool_source") or tool_name),
                "source_type": source_type,
                "cve_id": cve_id,
                "cvss_score": _normalize_cvss_score(item.get("cvss_score")),
                "evidence": evidence,
                "exploitability": item.get("exploitability"),
                "surface": item.get("surface"),
                "route_group": item.get("route_group"),
                "vulnerability_type": item.get("vulnerability_type"),
                "entity_key": _entity_key("vulnerability", fingerprint)
                if source_type != "exploit_verify"
                else _entity_key("privilege", f"{target}:{title}"),
            }
        )

    return _dedupe_findings(findings)


def _extract_evidence(
    *,
    tool_name: str,
    artifact_type: str,
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    evidence_items: dict[str, dict[str, Any]] = {}
    for finding in findings:
        fingerprint = str(finding["fingerprint"])
        evidence = finding.get("evidence") or {}
        if not isinstance(evidence, dict):
            continue

        for evidence_type in ("request", "response", "payload", "exploit_result"):
            content = evidence.get(evidence_type)
            if not content:
                continue

            candidate = {
                "id": f"{fingerprint}:{evidence_type}",
                "finding_fingerprint": fingerprint,
                "evidence_type": evidence_type,
                "label": f"{finding['title']} · {evidence_type.replace('_', ' ')}",
                "target": str(evidence.get("endpoint") or evidence.get("target") or "unknown"),
                "severity": finding["severity"],
                "tool_source": tool_name,
                "content_preview": str(content)[:240],
                "content": str(content),
                "metadata": {
                    "artifact_type": artifact_type,
                    "finding_title": finding["title"],
                },
            }
            evidence_items[_evidence_item_key(candidate)] = candidate

        references = evidence.get("references")
        if isinstance(references, list):
            for index, reference in enumerate(references):
                candidate = {
                    "id": f"{fingerprint}:reference:{index}",
                    "finding_fingerprint": fingerprint,
                    "evidence_type": "reference",
                    "label": f"{finding['title']} · reference",
                    "target": str(evidence.get("endpoint") or evidence.get("target") or "unknown"),
                    "severity": finding["severity"],
                    "tool_source": tool_name,
                    "content_preview": str(reference)[:240],
                    "content": str(reference),
                    "metadata": {
                        "artifact_type": artifact_type,
                        "finding_title": finding["title"],
                    },
                }
                evidence_items.setdefault(_evidence_item_key(candidate), candidate)

    return list(evidence_items.values())


def _extract_relationships(
    *,
    artifact_type: str,
    items: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    raw_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    relationships: list[dict[str, Any]] = []

    if artifact_type == "services":
        for item in items:
            relationships.append(
                {
                    "source_key": _entity_key("asset", item["host"]),
                    "target_key": item["entity_key"],
                    "edge_type": "discovery",
                }
            )

    if artifact_type == "endpoints":
        for item in items:
            host = item.get("host") or item.get("url")
            relationships.append(
                {
                    "source_key": _entity_key("asset", str(host)),
                    "target_key": item["entity_key"],
                    "edge_type": "discovery",
                }
            )
            discovered_from = str(item.get("discovered_from") or "").strip()
            if discovered_from:
                relationships.append(
                    {
                        "source_key": _entity_key("endpoint", discovered_from),
                        "target_key": item["entity_key"],
                        "edge_type": "workflow",
                    }
                )
            if item.get("requires_auth"):
                relationships.append(
                    {
                        "source_key": _entity_key("entrypoint", "unauthenticated"),
                        "target_key": item["entity_key"],
                        "edge_type": "authenticated_access",
                    }
                )

    if artifact_type in _VULNERABILITY_ARTIFACT_TYPES:
        for finding in findings:
            source_target = finding.get("endpoint") or finding.get("target")
            if source_target:
                source_kind = "endpoint" if "://" in str(source_target) else "asset"
                relationships.append(
                    {
                        "source_key": _entity_key(source_kind, str(source_target)),
                        "target_key": _entity_key("vulnerability", str(finding["fingerprint"])),
                        "edge_type": "discovery",
                    }
                )

    if artifact_type in _IMPACT_ARTIFACT_TYPES:
        for finding in findings:
            relationships.append(
                {
                    "source_key": _entity_key("vulnerability", str(finding["fingerprint"])),
                    "target_key": _entity_key(
                        "privilege",
                        f"{finding.get('target', 'unknown')}:{finding['title']}",
                    ),
                    "edge_type": "exploit",
                }
            )

    for container in raw_items:
        workflows = container.get("workflows")
        if not isinstance(workflows, list):
            continue
        for workflow in workflows:
            source_url = str(workflow.get("source_url") or "").strip()
            target_url = str(workflow.get("target_url") or "").strip()
            if not source_url or not target_url:
                continue
            relationships.append(
                {
                    "source_key": _entity_key("endpoint", source_url),
                    "target_key": _entity_key("endpoint", target_url),
                    "edge_type": str(workflow.get("action") or "workflow"),
                }
            )

    return relationships


def _build_summary(
    *,
    tool_name: str,
    artifact_type: str,
    items: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    guardrail_stats: dict[str, int],
    scan_config: dict[str, Any],
    raw_items: list[dict[str, Any]],
    stateful_context: dict[str, Any],
) -> dict[str, Any]:
    severity_counts = {severity: 0 for severity in _SEVERITY_ORDER}
    exploitability_counts = {"high": 0, "medium": 0, "low": 0}
    surface_counts = {"api": 0, "web": 0, "unknown": 0}
    technology_counts: dict[str, int] = {}
    for finding in findings:
        severity_counts[_normalize_severity(finding.get("severity"))] += 1
        exploitability = str(finding.get("exploitability") or "low").lower()
        if exploitability not in exploitability_counts:
            exploitability = "low"
        exploitability_counts[exploitability] += 1

        finding_evidence = finding.get("evidence") or {}
        if isinstance(finding_evidence, dict):
            classification = finding_evidence.get("classification") or {}
            if isinstance(classification, dict):
                surface = str(classification.get("surface") or "unknown").lower()
                if surface not in surface_counts:
                    surface = "unknown"
                surface_counts[surface] += 1

                technology = str(classification.get("primary_technology") or "").strip()
                if technology:
                    technology_counts[technology] = technology_counts.get(technology, 0) + 1

    highlights = [str(finding.get("title")) for finding in findings[:3]]
    targets: list[str] = []
    for item in items[:10]:
        target = item.get("target") or item.get("host") or item.get("url")
        if target:
            targets.append(str(target))

        technology = str(item.get("primary_technology") or "").strip()
        if technology:
            technology_counts[technology] = technology_counts.get(technology, 0) + 1

        item_surface = str(item.get("surface") or "unknown").lower()
        if item_surface in surface_counts:
            surface_counts[item_surface] += 1

    summary = {
        "tool": tool_name,
        "artifact_type": artifact_type,
        "item_count": len(items),
        "finding_count": len(findings),
        "evidence_count": len(evidence),
        "severity_counts": severity_counts,
        "exploitability_counts": exploitability_counts,
        "surface_counts": surface_counts,
        "technology_counts": technology_counts,
        "highlights": highlights,
        "targets": sorted(set(targets)),
        "guardrail_stats": guardrail_stats,
        "profile_id": scan_config.get("profile_id"),
    }
    if any(stateful_context.values()):
        summary["stateful_context"] = stateful_context
    if tool_name == "web_interact":
        summary["highlights"] = [
            f"Authenticated sessions: {stateful_context.get('session_count', 0)}",
            f"Discovered forms: {stateful_context.get('form_count', 0)}",
            f"Safe replays: {stateful_context.get('replay_count', 0)}",
        ]
    return summary


def _apply_scope_guardrails(
    *,
    artifact_type: str,
    items: list[dict[str, Any]],
    scan_config: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    scope = scan_config.get("scope", {})
    if not isinstance(scope, dict):
        scope = {}

    if not items:
        return [], {"filtered_out_of_scope": 0, "truncated": 0}

    allowed_hosts = {
        str(host).strip().lower()
        for host in scope.get("allowed_hosts", [])
        if str(host).strip()
    }
    allowed_domains = {
        str(domain).strip().lower()
        for domain in scope.get("allowed_domains", [])
        if str(domain).strip()
    }
    include_subdomains = bool(scope.get("include_subdomains", True))

    filtered: list[dict[str, Any]] = []
    filtered_out = 0
    for item in _sort_items(items):
        host = _item_host(artifact_type, item)
        if host and not _in_allowed_scope(
            host=host,
            allowed_hosts=allowed_hosts,
            allowed_domains=allowed_domains,
            include_subdomains=include_subdomains,
        ):
            filtered_out += 1
            continue
        filtered.append(item)

    limit = None
    if artifact_type in {"subdomains", "hosts"}:
        limit = int(scope.get("max_subdomains") or 0) or None
    elif artifact_type in {"endpoints", "vulnerabilities", "findings_scored"}:
        limit = int(scope.get("max_endpoints") or 0) or None

    truncated = 0
    if limit is not None and len(filtered) > limit:
        truncated = len(filtered) - limit
        filtered = filtered[:limit]

    return filtered, {
        "filtered_out_of_scope": filtered_out,
        "truncated": truncated,
    }


def _item_host(artifact_type: str, item: dict[str, Any]) -> str:
    if artifact_type in {"subdomains", "hosts", "services"}:
        return str(item.get("host") or item.get("target") or "").strip().lower()

    if artifact_type in {"endpoints", "vulnerabilities", "findings_scored"}:
        candidate = str(
            item.get("host")
            or item.get("endpoint")
            or item.get("url")
            or item.get("target")
            or ""
        ).strip()
        return _host_from_url(candidate).lower()

    if artifact_type in _IMPACT_ARTIFACT_TYPES:
        return _host_from_url(str(item.get("target") or "")).lower()

    return ""


def _extract_stateful_context(raw_items: list[dict[str, Any]]) -> dict[str, int]:
    session_labels: set[str] = set()
    form_count = 0
    workflow_count = 0
    replay_count = 0
    authenticated_page_count = 0

    for item in raw_items:
        sessions = item.get("sessions")
        if isinstance(sessions, list):
            for session in sessions:
                label = str(session.get("session_label") or "").strip()
                if label:
                    session_labels.add(label)

        forms = item.get("forms")
        if isinstance(forms, list):
            form_count += len(forms)

        workflows = item.get("workflows")
        if isinstance(workflows, list):
            workflow_count += len(workflows)

        replays = item.get("replays")
        if isinstance(replays, list):
            replay_count += len(replays)

        pages = item.get("pages")
        if isinstance(pages, list):
            authenticated_page_count += sum(
                1
                for page in pages
                if page.get("requires_auth") or str(page.get("auth_state") or "none") != "none"
            )

    return {
        "session_count": len(session_labels),
        "form_count": form_count,
        "workflow_count": workflow_count,
        "replay_count": replay_count,
        "authenticated_page_count": authenticated_page_count,
    }


def _in_allowed_scope(
    *,
    host: str,
    allowed_hosts: set[str],
    allowed_domains: set[str],
    include_subdomains: bool,
) -> bool:
    normalized = host.strip().lower()
    if not normalized:
        return True

    if not allowed_hosts and not allowed_domains:
        return True

    if normalized in allowed_hosts or normalized in allowed_domains:
        return True

    if include_subdomains:
        for domain in allowed_domains | allowed_hosts:
            if domain and normalized.endswith(f".{domain}"):
                return True

    return False


def _sort_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (
            str(item.get("host") or ""),
            str(item.get("url") or ""),
            str(item.get("target") or ""),
            str(item.get("title") or ""),
            str(item.get("finding_key") or ""),
        ),
    )


def _normalize_technologies(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw_values = [value]
    elif isinstance(value, list):
        raw_values = [str(item) for item in value if item]
    else:
        raw_values = [str(value)]

    technologies: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        for item in raw.replace(";", ",").split(","):
            normalized = item.strip()
            lowered = normalized.lower()
            if not normalized or lowered in seen:
                continue
            seen.add(lowered)
            technologies.append(normalized)
    return technologies


def _classify_surface(target: str, item: dict[str, Any]) -> str:
    candidate = f"{target} {item.get('title', '')} {item.get('description', '')}".lower()
    if any(token in candidate for token in ("/api/", "swagger", "openapi", "graphql", "json")):
        return "api"
    return "web"


def _route_group(target: str | None) -> str | None:
    if not target:
        return None

    path = _path_from_url(str(target)).strip()
    if not path or path == "/":
        return "/"

    segments: list[str] = []
    for segment in path.strip("/").split("/"):
        lowered = segment.lower()
        if lowered.isdigit():
            segments.append("{id}")
        elif len(lowered) >= 8 and any(char.isdigit() for char in lowered):
            segments.append("{token}")
        else:
            segments.append(lowered)
    return "/" + "/".join(segments)


def _classify_finding_family(
    *,
    title: str,
    description: str,
    tool_name: str,
    target: str,
    payload: Any,
) -> str:
    text = " ".join(
        part for part in (title, description, str(payload or ""), tool_name, target) if part
    ).lower()
    family_rules = [
        ("sql_injection", ("sql injection", "injectable", "sqli")),
        ("idor", ("idor", "broken access control", "object level authorization")),
        ("auth_bypass", ("authorization bypass", "auth bypass", "cross_session")),
        ("workflow_bypass", ("workflow bypass", "step bypass", "skip_step", "swap_order", "repeat_step")),
        ("privilege_escalation", ("privilege escalation", "privilege indicators")),
        ("unsafe_deserialization", ("deserialization", "serialized object", "ysoserial")),
        ("openapi_exposure", ("openapi", "swagger")),
        ("graphql_introspection", ("graphql", "introspection")),
        ("debug_exposure", ("debug", "stack trace")),
        ("cors_misconfiguration", ("cors", "access-control-allow-origin")),
        ("credential_exposure", ("credential", "secret", "token leak")),
    ]
    for family, patterns in family_rules:
        if any(pattern in text for pattern in patterns):
            return family
    return _slugify(title)


def _classify_exploitability(
    *,
    title: str,
    severity: str,
    confidence: int,
    tool_name: str,
    payload: Any,
    exploit_result: Any,
) -> str:
    text = " ".join(part for part in (title, tool_name, str(payload or ""), str(exploit_result or "")) if part).lower()
    if exploit_result or any(token in text for token in ("confirmed", "verified", "shell", "rce", "sqli", "idor")):
        return "high"
    if _normalize_severity(severity) in {"critical", "high"} and confidence >= 85:
        return "high"
    if confidence >= 70 or _normalize_severity(severity) == "medium":
        return "medium"
    return "low"


def _exploitability_score(level: str) -> int:
    return {"high": 90, "medium": 65, "low": 35}.get(level, 35)


def _verification_state_for_source(source_type: str) -> str:
    return {
        "scanner": "detected",
        "ai_analysis": "suspected",
        "exploit_verify": "verified",
    }.get(source_type, "detected")


def _infer_primary_technology(item: dict[str, Any], target: str) -> str:
    technologies = _normalize_technologies(
        item.get("technologies")
        or item.get("tech")
        or item.get("tech_stack")
        or item.get("technology")
    )
    if technologies:
        return technologies[0]

    text = f"{target} {item.get('description', '')} {item.get('title', '')}".lower()
    guesses = [
        ("GraphQL", ("graphql",)),
        ("Swagger UI", ("swagger", "openapi")),
        ("Java", ("java", "deserialization", "ysoserial")),
        ("PostgreSQL", ("postgres", "sql")),
        ("Next.js", ("next.js",)),
    ]
    for name, patterns in guesses:
        if any(pattern in text for pattern in patterns):
            return name
    return ""


def _merge_vulnerability_items(
    existing: dict[str, Any] | None,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    if existing is None:
        return candidate

    merged = dict(existing)
    if _severity_rank(candidate.get("severity", "info")) > _severity_rank(merged.get("severity", "info")):
        merged["severity"] = candidate.get("severity")
    merged["confidence"] = max(int(merged.get("confidence", 0) or 0), int(candidate.get("confidence", 0) or 0))
    merged["references"] = _merge_reference_values(
        list(merged.get("references") or []),
        list(candidate.get("references") or []),
    )
    for key in (
        "description",
        "remediation",
        "payload",
        "request",
        "response",
        "exploit_result",
        "primary_technology",
    ):
        merged[key] = _prefer_non_empty(merged.get(key), candidate.get(key))
    if _exploitability_score(str(candidate.get("exploitability", "low"))) > _exploitability_score(str(merged.get("exploitability", "low"))):
        merged["exploitability"] = candidate.get("exploitability")
        merged["exploitability_score"] = candidate.get("exploitability_score")
    return merged


def _prefer_non_empty(current: Any, candidate: Any) -> Any:
    current_value = str(current or "")
    candidate_value = str(candidate or "")
    if not current_value:
        return candidate
    if len(candidate_value) > len(current_value):
        return candidate
    return current


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for finding in findings:
        fingerprint = str(finding.get("fingerprint") or uuid.uuid4().hex)
        existing = deduped.get(fingerprint)
        if existing is None:
            deduped[fingerprint] = finding
            continue
        deduped[fingerprint] = _merge_finding(existing, finding)
    return list(deduped.values())


def _merge_finding(existing: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    if _severity_rank(candidate.get("severity", "info")) > _severity_rank(merged.get("severity", "info")):
        merged["severity"] = candidate.get("severity")
    merged["confidence"] = max(int(merged.get("confidence", 0) or 0), int(candidate.get("confidence", 0) or 0))
    for key in ("description", "remediation", "exploitability", "surface", "route_group", "vulnerability_type"):
        merged[key] = _prefer_non_empty(merged.get(key), candidate.get(key))

    merged_evidence = merged.get("evidence") or {}
    candidate_evidence = candidate.get("evidence") or {}
    if not isinstance(merged_evidence, dict):
        merged_evidence = {}
    if not isinstance(candidate_evidence, dict):
        candidate_evidence = {}

    references = merged_evidence.get("references") or []
    candidate_references = candidate_evidence.get("references") or []
    if not isinstance(references, list):
        references = []
    if not isinstance(candidate_references, list):
        candidate_references = []

    merged["evidence"] = {
        **merged_evidence,
        **{key: value for key, value in candidate_evidence.items() if value},
        "references": _merge_reference_values(references, candidate_references),
    }
    return merged


def _evidence_item_key(item: dict[str, Any]) -> str:
    return "|".join(
        [
            str(item.get("evidence_type") or "reference"),
            str(item.get("target") or ""),
            str(item.get("content_preview") or ""),
        ]
    )


def _merge_reference_values(*collections: list[Any]) -> list[Any]:
    merged: list[Any] = []
    seen: set[str] = set()
    for collection in collections:
        for reference in collection:
            signature = json.dumps(reference, sort_keys=True, default=str)
            if signature in seen:
                continue
            seen.add(signature)
            merged.append(reference)
    return merged


def _normalize_severity(value: Any) -> str:
    normalized = str(value or "info").strip().lower()
    severity_map = {
        "crit": "critical",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "med": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "warning": "medium",
    }
    return severity_map.get(normalized, "info")


def _severity_rank(severity: str) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }.get(_normalize_severity(severity), 0)


def _normalize_confidence(value: Any, severity: str) -> int:
    if value is not None:
        try:
            return max(0, min(int(value), 100))
        except (TypeError, ValueError):
            pass

    defaults = {
        "critical": 95,
        "high": 90,
        "medium": 80,
        "low": 70,
        "info": 60,
    }
    return defaults[_normalize_severity(severity)]


def _normalize_cvss_score(value: Any) -> float | None:
    if value in (None, "", []):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_cve_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)] if str(value).strip() else []


def _entity_key(kind: str, value: str) -> str:
    return f"{kind}:{value.strip().lower()}"


def _finding_key(family: str, target: str, route_group: str, cve_id: str) -> str:
    return sha256_json(
        {"family": family, "target": target, "route_group": route_group, "cve_id": cve_id}
    )


def _impact_title(artifact_type: str, access_level: str) -> str:
    title_map = {
        "access_levels": "Verified system access",
        "database_access": "Verified database access",
        "shell_access": "Verified shell access",
        "credential_leak": "Leaked credential material",
        "privilege_escalation": "Privilege escalation verified",
        "verified_impact": "Verified business impact",
    }
    return f"{title_map.get(artifact_type, artifact_type.replace('_', ' ').title())} ({access_level})"


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return slug or "finding"


def _host_from_url(value: str) -> str:
    if "://" not in value:
        host = value.split("/", 1)[0]
        if ":" in host and not host.startswith("["):
            return host.split(":", 1)[0]
        return host

    try:
        host = value.split("://", 1)[1].split("/", 1)[0]
        if ":" in host and not host.startswith("["):
            return host.split(":", 1)[0]
        return host
    except IndexError:
        return value


def _path_from_url(value: str) -> str:
    if not value:
        return "/"

    if "://" in value:
        parsed = urlsplit(value)
        return parsed.path or "/"

    return "/" + value.split("?", 1)[0].split("#", 1)[0].strip("/").lstrip("/")


def _first_url(content: str) -> str | None:
    match = re.search(r"https?://[^\s'\"]+", content)
    if match:
        return match.group(0)
    return None


def _extract_payload(content: str) -> str | None:
    match = re.search(r"payload[:=]\s*(.+)", content, re.IGNORECASE)
    return match.group(1).strip() if match else None


def _strip_query_fragment(value: str) -> str:
    if "://" not in value:
        return value.split("?", 1)[0].split("#", 1)[0]
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


# ── Output parsers ───────────────────────────────────────────────────


def _parse_output(output_dir: str, parser: str) -> list[dict[str, Any]]:
    """Parse raw tool output into a list of normalized items."""
    output_path = Path(output_dir)

    if parser == "json":
        return _parse_json(output_path)
    if parser == "xml_nmap":
        return _parse_nmap_xml(output_path)
    if parser == "csv":
        return _parse_csv(output_path)
    if parser == "scope":
        return _parse_json(output_path)
    return _parse_raw(output_path)


def _parse_json(output_path: Path) -> list[dict[str, Any]]:
    """Parse JSON output files."""
    items: list[dict[str, Any]] = []
    for file_path in output_path.glob("*.json"):
        try:
            content = file_path.read_text()
            if not content.strip():
                continue

            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                if "\n" not in content.strip():
                    raise
                for line in content.strip().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(data, dict):
                        items.append(data)
                continue

            if isinstance(data, list):
                items.extend([item for item in data if isinstance(item, dict)])
            elif isinstance(data, dict):
                items.append(data)
        except Exception:
            logger.warning("Failed to parse JSON file: %s", file_path)
    return items


def _parse_nmap_xml(output_path: Path) -> list[dict[str, Any]]:
    """Parse Nmap XML output into normalized host/service records."""
    items: list[dict[str, Any]] = []
    for file_path in output_path.glob("*.xml"):
        try:
            tree = ET.parse(str(file_path))
            root = tree.getroot()

            for host in root.findall(".//host"):
                addr_el = host.find("address")
                addr = addr_el.get("addr", "") if addr_el is not None else ""
                status_el = host.find("status")
                state = status_el.get("state", "") if status_el is not None else ""

                host_entry: dict[str, Any] = {
                    "host": addr,
                    "state": state,
                    "ports": [],
                }

                for port in host.findall(".//port"):
                    svc_el = port.find("service")
                    port_entry = {
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", ""),
                        "state": "",
                        "service": "",
                        "version": "",
                    }
                    state_el = port.find("state")
                    if state_el is not None:
                        port_entry["state"] = state_el.get("state", "")
                    if svc_el is not None:
                        port_entry["service"] = svc_el.get("name", "")
                        port_entry["version"] = svc_el.get("version", "")
                    host_entry["ports"].append(port_entry)

                items.append(host_entry)
        except Exception:
            logger.warning("Failed to parse Nmap XML: %s", file_path)
    return items


def _parse_csv(output_path: Path) -> list[dict[str, Any]]:
    """Parse CSV output files."""
    import csv as csv_mod

    items: list[dict[str, Any]] = []
    for file_path in output_path.glob("*.csv"):
        try:
            with file_path.open() as handle:
                reader = csv_mod.DictReader(handle)
                for row in reader:
                    items.append(dict(row))
        except Exception:
            logger.warning("Failed to parse CSV: %s", file_path)
    return items


def _parse_raw(output_path: Path) -> list[dict[str, Any]]:
    """Parse raw text output by wrapping each file as a blob."""
    items: list[dict[str, Any]] = []
    for file_path in sorted(output_path.rglob("*")):
        if file_path.is_file():
            try:
                if file_path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}:
                    continue
                content = file_path.read_text(errors="replace")[:50_000]
                if not content.strip():
                    continue
                items.append(
                    {
                        "filename": file_path.name,
                        "path": str(file_path.relative_to(output_path)),
                        "content": content,
                        "size_bytes": file_path.stat().st_size,
                    }
                )
            except Exception:
                pass
    return items


def _get_output_size(output_dir: str) -> int:
    """Sum the size of all files in the output directory."""
    total = 0
    for file_path in Path(output_dir).rglob("*"):
        if file_path.is_file():
            total += file_path.stat().st_size
    return total
