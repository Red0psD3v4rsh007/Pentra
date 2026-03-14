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
) -> dict[str, Any]:
    """Read raw tool output and normalize it into Pentra's canonical artifact."""
    raw_items = _parse_output(output_dir, output_parser)
    raw_size = _get_output_size(output_dir)

    items = _canonicalize_items(
        tool_name=tool_name,
        artifact_type=artifact_type,
        raw_items=raw_items,
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
    relationships = _extract_relationships(
        artifact_type=artifact_type,
        items=items,
        findings=findings,
    )
    summary = _build_summary(
        tool_name=tool_name,
        artifact_type=artifact_type,
        items=items,
        findings=findings,
        evidence=evidence,
    )

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


def _canonicalize_items(
    *,
    tool_name: str,
    artifact_type: str,
    raw_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
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
    items: list[dict[str, Any]] = []
    for item in raw_items:
        host = str(item.get("host", item.get("target", item.get("name", "unknown"))))
        asset = {
            **item,
            "host": host,
            "entity_key": _entity_key("asset", host),
        }
        items.append(asset)
    return items


def _canonicalize_services(raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
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
            services.append(service_item)
    return services


def _canonicalize_endpoints(raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    for item in raw_items:
        nested = item.get("results")
        if isinstance(nested, list):
            endpoints.extend(_canonicalize_endpoints(nested))
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
        endpoint = {
            "url": url,
            "host": host,
            "path": _path_from_url(url),
            "status_code": int(item.get("status_code", item.get("status", 0) or 0)),
            "content_length": int(item.get("content_length", item.get("length", 0) or 0)),
            "words": int(item.get("words", 0) or 0),
            "entity_key": _entity_key("endpoint", url),
        }
        endpoints.append(endpoint)
    return endpoints


def _canonicalize_vulnerabilities(
    tool_name: str,
    raw_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for item in raw_items:
        if tool_name == "zap" and isinstance(item.get("alerts"), list):
            items.extend(_canonicalize_vulnerabilities(tool_name, item["alerts"]))
            continue

        if tool_name.startswith("sqlmap"):
            items.append(_canonicalize_sqlmap_item(item))
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
        finding_key = _finding_key(tool_name, title, target, cve_values[0] if cve_values else "")

        vuln_item = {
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "target": target_host or target,
            "endpoint": target if "://" in target or target.startswith("/") else None,
            "description": description,
            "remediation": remediation,
            "tool_source": tool_name,
            "vulnerability_type": _slugify(title),
            "cve_id": cve_values[0] if cve_values else None,
            "cve_ids": cve_values,
            "cvss_score": cvss_score,
            "request": request,
            "response": response,
            "payload": payload,
            "exploit_result": exploit_result,
            "references": item.get("reference") or item.get("references") or [],
            "finding_key": finding_key,
        }
        items.append(vuln_item)
    return items


def _canonicalize_sqlmap_item(item: dict[str, Any]) -> dict[str, Any]:
    content = str(item.get("content", "")).strip()
    target = _first_url(content) or str(item.get("filename", "sqlmap-target"))
    return {
        "title": "SQL Injection confirmed via sqlmap",
        "severity": "critical",
        "confidence": 95,
        "target": _host_from_url(target) or target,
        "endpoint": target,
        "description": content[:1000] or "sqlmap reported injectable parameters.",
        "remediation": "Use parameterized queries and server-side input validation.",
        "tool_source": "sqlmap",
        "vulnerability_type": "sql_injection",
        "cve_id": None,
        "cve_ids": [],
        "cvss_score": 9.8,
        "content": content,
        "payload": _extract_payload(content),
        "request": item.get("request"),
        "response": item.get("response"),
        "references": [],
        "finding_key": _finding_key("sqlmap", "SQL Injection confirmed via sqlmap", target, ""),
    }


def _canonicalize_impacts(
    tool_name: str,
    artifact_type: str,
    raw_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
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
            "entity_key": _entity_key("privilege", f"{target}:{access_level}"),
        }
        items.append(impact_item)
    return items


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

    for item in items:
        title = str(item.get("title") or item.get("name") or f"{tool_name} finding")
        severity = _normalize_severity(item.get("severity"))
        target = str(item.get("target") or item.get("endpoint") or "unknown")
        endpoint = item.get("endpoint")
        cve_id = item.get("cve_id")
        fingerprint = sha256_json(
            {
                "tool": tool_name,
                "artifact_type": artifact_type,
                "title": title,
                "target": target,
                "endpoint": endpoint,
                "cve_id": cve_id,
                "description": item.get("description"),
                "payload": item.get("payload"),
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
        }
        findings.append(
            {
                "fingerprint": fingerprint,
                "title": title,
                "severity": severity,
                "confidence": int(item.get("confidence") or _normalize_confidence(None, severity)),
                "target": target,
                "endpoint": endpoint,
                "description": item.get("description"),
                "remediation": item.get("remediation"),
                "tool_source": str(item.get("tool_source") or tool_name),
                "source_type": source_type,
                "cve_id": cve_id,
                "cvss_score": _normalize_cvss_score(item.get("cvss_score")),
                "evidence": evidence,
                "entity_key": _entity_key("vulnerability", fingerprint)
                if source_type != "exploit_verify"
                else _entity_key("privilege", f"{target}:{title}"),
            }
        )

    return findings


def _extract_evidence(
    *,
    tool_name: str,
    artifact_type: str,
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    evidence_items: list[dict[str, Any]] = []
    for finding in findings:
        fingerprint = str(finding["fingerprint"])
        evidence = finding.get("evidence") or {}
        if not isinstance(evidence, dict):
            continue

        for evidence_type in ("request", "response", "payload", "exploit_result"):
            content = evidence.get(evidence_type)
            if not content:
                continue

            evidence_items.append(
                {
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
            )

        references = evidence.get("references")
        if isinstance(references, list):
            for index, reference in enumerate(references):
                evidence_items.append(
                    {
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
                )

    return evidence_items


def _extract_relationships(
    *,
    artifact_type: str,
    items: list[dict[str, Any]],
    findings: list[dict[str, Any]],
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

    return relationships


def _build_summary(
    *,
    tool_name: str,
    artifact_type: str,
    items: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    severity_counts = {severity: 0 for severity in _SEVERITY_ORDER}
    for finding in findings:
        severity_counts[_normalize_severity(finding.get("severity"))] += 1

    highlights = [str(finding.get("title")) for finding in findings[:3]]
    targets = []
    for item in items[:10]:
        target = item.get("target") or item.get("host") or item.get("url")
        if target:
            targets.append(str(target))

    return {
        "tool": tool_name,
        "artifact_type": artifact_type,
        "item_count": len(items),
        "finding_count": len(findings),
        "evidence_count": len(evidence),
        "severity_counts": severity_counts,
        "highlights": highlights,
        "targets": targets,
    }


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


def _finding_key(tool_name: str, title: str, target: str, cve_id: str) -> str:
    return sha256_json(
        {"tool": tool_name, "title": title, "target": target, "cve_id": cve_id}
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
        return value.split("/")[0]

    try:
        return value.split("://", 1)[1].split("/", 1)[0]
    except IndexError:
        return value


def _path_from_url(value: str) -> str:
    if "://" not in value or "/" not in value.split("://", 1)[1]:
        return "/"
    return "/" + value.split("://", 1)[1].split("/", 1)[1]


def _first_url(content: str) -> str | None:
    match = re.search(r"https?://[^\s'\"]+", content)
    if match:
        return match.group(0)
    return None


def _extract_payload(content: str) -> str | None:
    match = re.search(r"payload[:=]\s*(.+)", content, re.IGNORECASE)
    return match.group(1).strip() if match else None


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

            if "\n" in content.strip() and not content.strip().startswith("["):
                for line in content.strip().splitlines():
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(data, dict):
                            items.append(data)
                continue

            data = json.loads(content)
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
    for file_path in sorted(output_path.iterdir()):
        if file_path.is_file():
            try:
                content = file_path.read_text(errors="replace")[:50_000]
                items.append(
                    {
                        "filename": file_path.name,
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
