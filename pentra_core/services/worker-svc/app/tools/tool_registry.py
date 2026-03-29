"""Tool registry — loads ToolDefinitions from YAML spec files.

All tool behavior is data-driven.  No hardcoded Python tool functions.
YAML specs live in ``app/tools/specs/*.yaml`` and are loaded at import time.

Usage::

    from app.tools.tool_registry import get_tool, get_all_tools

    tool = get_tool("subfinder")
    print(tool.image, tool.command)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class _FormatContext(dict):
    def __missing__(self, key: str) -> str:
        return ""

# ── Data model ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class ToolDefinition:
    """Specification for a security tool loaded from YAML."""

    name: str
    worker_family: str  # recon | network | web | vuln | exploit
    image: str          # Docker image
    command: list[str]  # Command template (supports {target}, {output_dir}, etc.)
    output_parser: str  # json | xml_nmap | csv | raw | scope
    artifact_type: str  # subdomains | hosts | services | vulnerabilities | etc.
    default_timeout: int = 600
    env_vars: dict[str, str] = field(default_factory=dict)
    working_dir: str | None = None
    entrypoint: list[str] | None = None


# ── Registry ─────────────────────────────────────────────────────────

_REGISTRY: dict[str, ToolDefinition] = {}
_SPECS_DIR = Path(__file__).parent / "specs"


def _load_specs() -> None:
    """Load all YAML spec files from the specs directory."""
    if not _SPECS_DIR.is_dir():
        logger.warning("Tool specs directory not found: %s", _SPECS_DIR)
        return

    for path in sorted(_SPECS_DIR.glob("*.yaml")):
        try:
            with open(path) as f:
                data = yaml.safe_load(f)

            tool = ToolDefinition(
                name=data["name"],
                worker_family=data["worker_family"],
                image=data["image"],
                command=data["command"],
                output_parser=data.get("output_parser", "raw"),
                artifact_type=data.get("artifact_type", "tool_output"),
                default_timeout=data.get("default_timeout", 600),
                env_vars=data.get("env_vars", {}),
                working_dir=data.get("working_dir"),
                entrypoint=data.get("entrypoint"),
            )
            _REGISTRY[tool.name] = tool
            logger.debug("Loaded tool spec: %s (%s)", tool.name, path.name)

        except Exception:
            logger.exception("Failed to load tool spec: %s", path)

    logger.info("Tool registry loaded: %d tools", len(_REGISTRY))


def get_tool(name: str) -> ToolDefinition | None:
    """Look up a tool definition by name."""
    return _REGISTRY.get(name)


def get_all_tools() -> dict[str, ToolDefinition]:
    """Return all loaded tool definitions."""
    return dict(_REGISTRY)


def get_tools_for_family(family: str) -> list[ToolDefinition]:
    """Return all tools belonging to a worker family."""
    return [t for t in _REGISTRY.values() if t.worker_family == family]


def render_command(
    tool: ToolDefinition,
    *,
    target: str,
    output_dir: str,
    input_dir: str = "",
    config_file: str = "",
    context: dict[str, Any] | None = None,
) -> list[str]:
    """Render a tool's command template with runtime values."""
    values = _FormatContext(
        {
        "target": target,
        "output_dir": output_dir,
        "input_dir": input_dir,
        "config_file": config_file,
        }
    )
    if context:
        values.update(
            {
                key: value if isinstance(value, str) else str(value)
                for key, value in context.items()
            }
        )

    return [
        part.format_map(values)
        for part in tool.command
    ]


# Auto-load specs on import
_load_specs()
