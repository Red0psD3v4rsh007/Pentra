"""Artifact resolver — downloads upstream tool outputs for downstream consumption.

When a DAG edge carries a data_ref (storage reference to an upstream tool's
output), the downstream tool needs the ACTUAL DATA, not just the ref string.

This module:
  1. Reads the storage ref from the .ref file
  2. Downloads the artifact content from local/S3 storage
  3. Writes the data as a usable file (.json, .txt) in the input directory
  4. Handles format conversion (e.g., JSON → newline-separated list for tools
     that expect line-delimited input like httpx, nuclei)

Usage::

    from app.engine.artifact_resolver import ArtifactResolver

    resolver = ArtifactResolver()
    await resolver.resolve_input_refs(input_dir=work_dir / "input")
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pentra_common.storage.artifacts import get_artifact_store_root, resolve_storage_ref

logger = logging.getLogger(__name__)

# Maps upstream tool output keys to downstream-friendly file formats
# key → (output_filename, format)
_OUTPUT_FORMAT_MAP: dict[str, tuple[str, str]] = {
    "subdomains": ("subdomains.txt", "lines"),
    "hosts": ("hosts.txt", "lines"),
    "urls": ("urls.txt", "lines"),
    "endpoints": ("endpoints.json", "json"),
    "ports": ("ports.json", "json"),
    "services": ("services.json", "json"),
    "vulnerabilities": ("vulnerabilities.json", "json"),
    "directories": ("directories.txt", "lines"),
    "technologies": ("technologies.json", "json"),
    "parameters": ("parameters.json", "json"),
    "source_code": ("source.tar.gz", "binary"),
}


class ArtifactResolver:
    """Resolves .ref files in a tool's input directory to actual data files."""

    def __init__(self, storage_base: str | Path | None = None) -> None:
        """Initialize with optional storage base path.

        Args:
            storage_base: Base directory for local artifact storage.
                         Defaults to the shared artifact store root.
        """
        self._storage_base = (
            Path(storage_base)
            if storage_base is not None
            else get_artifact_store_root()
        )

    async def resolve_input_refs(self, input_dir: Path) -> int:
        """Scan input_dir for .ref files and resolve each to actual data.

        For each file like `subdomains.ref`:
          1. Read the storage reference string from it
          2. Load the artifact data
          3. Write as `subdomains.txt` or `subdomains.json` depending on type
          4. Remove the .ref file

        Returns:
            Number of refs successfully resolved.
        """
        if not input_dir.exists():
            return 0

        resolved = 0
        ref_files = list(input_dir.glob("*.ref"))

        for ref_file in ref_files:
            ref_key = ref_file.stem  # e.g., "subdomains" from "subdomains.ref"
            storage_ref = ref_file.read_text().strip()

            if not storage_ref:
                logger.warning("Empty ref file: %s", ref_file)
                continue

            try:
                data = self._load_artifact(storage_ref)
                if data is None:
                    logger.warning(
                        "Could not load artifact for ref %s (%s)",
                        ref_key, storage_ref,
                    )
                    continue

                # Determine output format
                out_name, fmt = _OUTPUT_FORMAT_MAP.get(
                    ref_key, (f"{ref_key}.json", "json")
                )
                out_path = input_dir / out_name

                self._write_data(out_path, data, fmt)
                resolved += 1

                logger.info(
                    "Resolved input ref: %s → %s (%d bytes)",
                    ref_key, out_name, out_path.stat().st_size,
                )

            except Exception:
                logger.exception(
                    "Failed to resolve ref %s from %s", ref_key, storage_ref,
                )

        if resolved:
            logger.info(
                "Resolved %d/%d input refs in %s",
                resolved, len(ref_files), input_dir,
            )

        return resolved

    def _load_artifact(self, storage_ref: str) -> Any | None:
        """Load artifact content from a storage reference.

        Supports:
          - Local file paths (file:///path/to/artifact.json)
          - Relative paths within storage base
          - Raw JSON strings (for inline refs)

        Returns:
            Parsed data (dict, list, or str), or None if not found.
        """
        # Handle file:// URIs
        if storage_ref.startswith("file://"):
            file_path = Path(storage_ref[7:])
        elif storage_ref.startswith("/"):
            file_path = Path(storage_ref)
        else:
            file_path = resolve_storage_ref(storage_ref, root=self._storage_base)

        if not file_path.exists():
            # Try with common extensions if path doesn't exist
            for ext in (".json", ".txt", ".csv"):
                candidate = file_path.with_suffix(ext)
                if candidate.exists():
                    file_path = candidate
                    break
            else:
                logger.debug("Artifact file not found: %s", file_path)
                return None

        content = file_path.read_text(errors="replace")

        # Try to parse as JSON
        try:
            return json.loads(content)
        except (json.JSONDecodeError, ValueError):
            # Return as raw string (could be line-delimited text)
            return content

    def _write_data(
        self, out_path: Path, data: Any, fmt: str,
    ) -> None:
        """Write resolved data to the output file in the appropriate format.

        Args:
            out_path: Target file path
            data: The loaded artifact data
            fmt: Output format — "json", "lines", or "binary"
        """
        if fmt == "json":
            if isinstance(data, (dict, list)):
                out_path.write_text(json.dumps(data, indent=2, default=str))
            else:
                out_path.write_text(str(data))

        elif fmt == "lines":
            lines = self._extract_lines(data)
            out_path.write_text("\n".join(lines) + "\n" if lines else "")

        elif fmt == "binary":
            if isinstance(data, bytes):
                out_path.write_bytes(data)
            else:
                out_path.write_text(str(data))

        else:
            out_path.write_text(str(data))

    def _extract_lines(self, data: Any) -> list[str]:
        """Extract a list of line items from various data formats.

        Handles:
          - List of strings → direct
          - List of dicts with 'host'/'url'/'domain'/'ip' keys → extract values
          - Dict with 'items'/'results'/'hosts'/'urls' keys → extract list
          - Raw string → split by newlines
        """
        if isinstance(data, list):
            lines = []
            for item in data:
                if isinstance(item, str):
                    lines.append(item.strip())
                elif isinstance(item, dict):
                    # Try common key names
                    for key in ("host", "url", "domain", "ip", "target", "subdomain", "value", "name"):
                        val = item.get(key)
                        if val:
                            lines.append(str(val).strip())
                            break
                    else:
                        # Fallback: stringify the entire dict
                        lines.append(json.dumps(item))
            return [line for line in lines if line]

        elif isinstance(data, dict):
            # Try common wrapper keys
            for key in ("items", "results", "hosts", "urls", "subdomains", "domains", "targets", "data"):
                items = data.get(key)
                if isinstance(items, list):
                    return self._extract_lines(items)
            # Single value dict
            return [str(v) for v in data.values() if v]

        elif isinstance(data, str):
            return [line.strip() for line in data.splitlines() if line.strip()]

        return []
