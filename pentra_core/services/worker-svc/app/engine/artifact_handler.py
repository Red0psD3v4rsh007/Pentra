"""Artifact handler — normalizes tool output and prepares storage references.

Reads raw tool output from the container's output directory,
normalizes it into a unified artifact schema, and produces
a storage reference string for the orchestrator's state manager.

Unified Artifact Schema::

    {
        "tool": "nuclei",
        "artifact_type": "vulnerabilities",
        "scan_id": "...",
        "node_id": "...",
        "tenant_id": "...",
        "timestamp": "2026-...",
        "item_count": 42,
        "items": [...],
        "metadata": {
            "exit_code": 0,
            "duration_ms": 12345,
            "raw_size_bytes": 8192,
        }
    }
"""

from __future__ import annotations

import json
import logging
import os
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Where normalized artifacts are stored (local fs or S3-compatible path)
ARTIFACT_STORE = os.getenv(
    "ARTIFACT_STORE_PATH",
    "/tmp/pentra/artifacts",
)



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
    """Read raw tool output and normalize into a unified artifact.

    Returns the normalized artifact dict.
    """
    raw_items = _parse_output(output_dir, output_parser)
    raw_size = _get_output_size(output_dir)

    artifact = {
        "tool": tool_name,
        "artifact_type": artifact_type,
        "scan_id": scan_id,
        "node_id": node_id,
        "tenant_id": tenant_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "item_count": len(raw_items),
        "items": raw_items,
        "metadata": {
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "raw_size_bytes": raw_size,
        },
    }

    return artifact


def store_artifact(
    artifact: dict[str, Any],
    *,
    scan_id: str,
    node_id: str,
    tenant_id: str,
    tool_name: str,
) -> str:
    """Store a normalized artifact and return a storage_ref string.

    In dev: writes to local filesystem.
    In prod: would write to S3 (same interface via storage_ref).

    Returns:
        storage_ref like "artifacts/{tenant_id}/{scan_id}/{node_id}/{tool}.json"
    """
    rel_path = f"{tenant_id}/{scan_id}/{node_id}/{tool_name}.json"
    full_path = Path(ARTIFACT_STORE) / rel_path
    full_path.parent.mkdir(parents=True, exist_ok=True)

    with open(full_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)

    storage_ref = f"artifacts/{rel_path}"
    logger.info(
        "Artifact stored: %s (%d items, %d bytes)",
        storage_ref, artifact.get("item_count", 0),
        artifact.get("metadata", {}).get("raw_size_bytes", 0),
    )
    return storage_ref


# ── Output parsers ───────────────────────────────────────────────────


def _parse_output(output_dir: str, parser: str) -> list[dict]:
    """Parse raw tool output into a list of normalized items."""
    output_path = Path(output_dir)

    if parser == "json":
        return _parse_json(output_path)
    elif parser == "xml_nmap":
        return _parse_nmap_xml(output_path)
    elif parser == "csv":
        return _parse_csv(output_path)
    elif parser == "scope":
        return _parse_json(output_path)  # scope is JSON
    else:  # raw
        return _parse_raw(output_path)


def _parse_json(output_path: Path) -> list[dict]:
    """Parse JSON output files."""
    items = []
    for f in output_path.glob("*.json"):
        try:
            content = f.read_text()
            if not content.strip():
                continue

            # Handle JSONL (one JSON object per line)
            if "\n" in content.strip() and not content.strip().startswith("["):
                for line in content.strip().splitlines():
                    line = line.strip()
                    if line:
                        try:
                            items.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            else:
                data = json.loads(content)
                if isinstance(data, list):
                    items.extend(data)
                elif isinstance(data, dict):
                    items.append(data)
        except Exception:
            logger.warning("Failed to parse JSON file: %s", f)
    return items


def _parse_nmap_xml(output_path: Path) -> list[dict]:
    """Parse Nmap XML output into normalized host/service records."""
    items = []
    for f in output_path.glob("*.xml"):
        try:
            tree = ET.parse(str(f))
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
            logger.warning("Failed to parse Nmap XML: %s", f)
    return items


def _parse_csv(output_path: Path) -> list[dict]:
    """Parse CSV output files."""
    import csv as csv_mod
    items = []
    for f in output_path.glob("*.csv"):
        try:
            with open(f) as fh:
                reader = csv_mod.DictReader(fh)
                for row in reader:
                    items.append(dict(row))
        except Exception:
            logger.warning("Failed to parse CSV: %s", f)
    return items


def _parse_raw(output_path: Path) -> list[dict]:
    """Parse raw text output — wraps each file as a blob."""
    items = []
    for f in sorted(output_path.iterdir()):
        if f.is_file():
            try:
                content = f.read_text(errors="replace")[:50_000]  # cap at 50KB
                items.append({
                    "filename": f.name,
                    "content": content,
                    "size_bytes": f.stat().st_size,
                })
            except Exception:
                pass
    return items


def _get_output_size(output_dir: str) -> int:
    """Sum the size of all files in the output directory."""
    total = 0
    for f in Path(output_dir).rglob("*"):
        if f.is_file():
            total += f.stat().st_size
    return total
