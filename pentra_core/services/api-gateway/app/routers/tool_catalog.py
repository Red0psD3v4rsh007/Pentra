"""Tool Catalog API — exposes the tool registry with human-friendly metadata.

Mounted at ``/api/v1/tools``.

Provides:
  - Full tool list with descriptions, subcommands, attack coverage
  - Individual tool details
  - Subcommand catalog with human descriptions
  - Command preview rendering
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.deps import CurrentUser, require_roles

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tools"])


# ═══════════════════════════════════════════════════════════════════════
#  Subcommand Metadata — human-friendly descriptions for every flag
# ═══════════════════════════════════════════════════════════════════════

TOOL_SUBCOMMANDS: dict[str, list[dict[str, Any]]] = {
    "subfinder": [
        {"flag": "-d", "description": "Target domain to enumerate subdomains for", "required": True, "category": "target"},
        {"flag": "-silent", "description": "Show only results, no banner or metadata", "default": True, "category": "output"},
        {"flag": "-o", "description": "Save results to output file", "default": True, "category": "output"},
        {"flag": "-all", "description": "Use all sources (slower but more complete)", "default": False, "category": "scope"},
        {"flag": "-recursive", "description": "Enable recursive subdomain enumeration", "default": False, "category": "scope"},
        {"flag": "-t", "description": "Number of concurrent threads (default: 10)", "default": 10, "category": "performance", "value_type": "int"},
        {"flag": "-timeout", "description": "Timeout per source in seconds", "default": 30, "category": "performance", "value_type": "int"},
    ],
    "nmap_discovery": [
        {"flag": "-sn", "description": "Ping scan — discover live hosts without port scanning", "default": True, "category": "scan_type"},
        {"flag": "-sV", "description": "Detect service versions on open ports", "default": True, "category": "scan_type"},
        {"flag": "-sC", "description": "Run default NSE scripts for service detection", "default": True, "category": "scan_type"},
        {"flag": "--top-ports", "description": "Scan the N most common ports", "default": 1000, "category": "scope", "value_type": "int"},
        {"flag": "-p-", "description": "Scan all 65535 ports (slower but complete)", "default": False, "category": "scope"},
        {"flag": "-T4", "description": "Aggressive timing for faster scans", "default": False, "category": "performance"},
        {"flag": "--script vuln,auth", "description": "Run vulnerability and auth NSE scripts", "default": False, "category": "vuln_detection"},
        {"flag": "-oX", "description": "Save output in XML format", "default": True, "category": "output"},
        {"flag": "-oN", "description": "Save output in normal text format", "default": True, "category": "output"},
    ],
    "nmap_svc": [
        {"flag": "-sV", "description": "Detect service versions", "default": True, "category": "scan_type"},
        {"flag": "-O", "description": "Enable OS detection", "default": True, "category": "scan_type"},
        {"flag": "-A", "description": "Aggressive scan (OS, version, scripts, traceroute)", "default": True, "category": "scan_type"},
        {"flag": "--version-intensity", "description": "Version detection intensity (0-9, higher = more probes)", "default": 9, "category": "depth", "value_type": "int"},
        {"flag": "-sU", "description": "UDP port scan (slow but reveals DNS, SNMP, etc.)", "default": False, "category": "scan_type"},
        {"flag": "--top-ports", "description": "Scan top N UDP ports", "default": 50, "category": "scope", "value_type": "int"},
    ],
    "httpx_probe": [
        {"flag": "-status-code", "description": "Show HTTP status codes in output", "default": True, "category": "output"},
        {"flag": "-title", "description": "Extract and show page titles", "default": True, "category": "output"},
        {"flag": "-tech-detect", "description": "Detect web technologies (frameworks, CMS, etc.)", "default": True, "category": "detection"},
        {"flag": "-follow-redirects", "description": "Follow HTTP redirects", "default": True, "category": "behavior"},
        {"flag": "-json", "description": "Output in JSON format", "default": True, "category": "output"},
        {"flag": "-content-length", "description": "Show response content length", "default": False, "category": "output"},
        {"flag": "-web-server", "description": "Show web server software", "default": False, "category": "detection"},
        {"flag": "-cdn", "description": "Detect CDN usage (Cloudflare, Akamai, etc.)", "default": False, "category": "detection"},
    ],
    "ffuf": [
        {"flag": "-u", "description": "Target URL with FUZZ keyword as placeholder", "required": True, "category": "target"},
        {"flag": "-w", "description": "Path to wordlist file for fuzzing", "required": True, "category": "wordlist"},
        {"flag": "-mc", "description": "Match HTTP status codes (comma-separated)", "default": "200,201,301,302,307,401,403,405", "category": "filter", "value_type": "string"},
        {"flag": "-rate", "description": "Requests per second rate limit", "default": 60, "category": "performance", "value_type": "int"},
        {"flag": "-e", "description": "File extensions to append (e.g., .php,.html,.js)", "default": "", "category": "scope", "value_type": "string"},
        {"flag": "-fc", "description": "Filter out these HTTP status codes", "default": "", "category": "filter", "value_type": "string"},
        {"flag": "-fs", "description": "Filter out responses with this size", "default": "", "category": "filter", "value_type": "string"},
        {"flag": "-recursion", "description": "Enable recursive fuzzing into discovered directories", "default": False, "category": "scope"},
        {"flag": "-recursion-depth", "description": "Maximum recursion depth", "default": 2, "category": "scope", "value_type": "int"},
        {"flag": "-of json", "description": "Output format (json, csv, html)", "default": True, "category": "output"},
    ],
    "nuclei": [
        {"flag": "-l", "description": "File containing list of target URLs", "required": True, "category": "target"},
        {"flag": "-u", "description": "Single target URL to scan", "required": False, "category": "target"},
        {"flag": "-t", "description": "Path to template directory or specific template", "default": True, "category": "templates"},
        {"flag": "-tags", "description": "Run templates matching these tags (e.g., sqli,xss,cve)", "default": "", "category": "templates", "value_type": "string"},
        {"flag": "-severity", "description": "Filter by severity levels", "default": "info,low,medium,high,critical", "category": "filter", "value_type": "string"},
        {"flag": "-rate-limit", "description": "Maximum requests per second", "default": 35, "category": "performance", "value_type": "int"},
        {"flag": "-bulk-size", "description": "Number of templates to run in parallel", "default": 25, "category": "performance", "value_type": "int"},
        {"flag": "-concurrency", "description": "Number of concurrent targets", "default": 10, "category": "performance", "value_type": "int"},
        {"flag": "-json", "description": "Output results in JSON format", "default": True, "category": "output"},
        {"flag": "-new-templates", "description": "Run only newly added templates", "default": False, "category": "templates"},
        {"flag": "-automatic-scan", "description": "Let Nuclei auto-select templates based on tech stack", "default": False, "category": "templates"},
    ],
    "sqlmap": [
        {"flag": "-u", "description": "Target URL with parameters to test for SQLi", "required": True, "category": "target"},
        {"flag": "--crawl", "description": "Crawl depth for discovering injectable URLs", "default": 3, "category": "scope", "value_type": "int"},
        {"flag": "--batch", "description": "Auto-answer all prompts (non-interactive mode)", "default": True, "category": "behavior"},
        {"flag": "--level", "description": "Test intensity level (1-5, higher = more tests)", "default": 3, "category": "depth", "value_type": "int"},
        {"flag": "--risk", "description": "Risk level (1-3, higher = more dangerous tests)", "default": 2, "category": "depth", "value_type": "int"},
        {"flag": "--threads", "description": "Number of concurrent threads", "default": 1, "category": "performance", "value_type": "int"},
        {"flag": "--forms", "description": "Test HTML form parameters", "default": True, "category": "scope"},
        {"flag": "--random-agent", "description": "Use random User-Agent header", "default": True, "category": "evasion"},
        {"flag": "--technique", "description": "SQL injection techniques (B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline)", "default": "BEUSTQ", "category": "technique", "value_type": "string"},
        {"flag": "--tamper", "description": "Tamper scripts for WAF bypass (e.g., space2comment,randomcase)", "default": "", "category": "evasion", "value_type": "string"},
        {"flag": "--dbs", "description": "Enumerate database names after finding injection", "default": False, "category": "exploitation"},
        {"flag": "--dump", "description": "Dump database table entries", "default": False, "category": "exploitation"},
    ],
    "nikto": [
        {"flag": "-h", "description": "Target host URL", "required": True, "category": "target"},
        {"flag": "-Format json", "description": "Output format (json, xml, htm, csv)", "default": True, "category": "output"},
        {"flag": "-Tuning", "description": "Scan tuning: 1=Files, 2=Misconfig, 3=Info, 4=XSS, 5=RCE, 6=Dirs, 7=Pharma, 8=Inject, 9=SQLi, 0=Upload, a=Auth, b=Software, c=Dirs", "default": "1234567890abc", "category": "scope", "value_type": "string"},
        {"flag": "-ssl", "description": "Test SSL/TLS configuration", "default": False, "category": "scope"},
        {"flag": "-evasion", "description": "IDS evasion technique (1-8)", "default": "", "category": "evasion", "value_type": "string"},
        {"flag": "-maxtime", "description": "Maximum scan time in seconds", "default": 300, "category": "performance", "value_type": "int"},
    ],
    "dalfox": [
        {"flag": "url", "description": "Scan a single URL for XSS", "required": True, "category": "target"},
        {"flag": "file", "description": "Scan URLs from a file (batch mode)", "required": False, "category": "target"},
        {"flag": "--silence", "description": "Suppress banner and info output", "default": True, "category": "output"},
        {"flag": "--no-color", "description": "Disable colored output", "default": True, "category": "output"},
        {"flag": "--format json", "description": "Output format (json, plain)", "default": True, "category": "output"},
        {"flag": "--timeout", "description": "HTTP request timeout in seconds", "default": 10, "category": "performance", "value_type": "int"},
        {"flag": "--delay", "description": "Delay between requests in milliseconds", "default": 100, "category": "rate_limit", "value_type": "int"},
        {"flag": "--skip-bav", "description": "Skip Basic/Abstract Vectors (faster scan)", "default": False, "category": "optimization"},
        {"flag": "--waf-evasion", "description": "Enable WAF evasion payloads", "default": False, "category": "evasion"},
        {"flag": "--deep-domxss", "description": "Deep DOM-based XSS analysis", "default": False, "category": "depth"},
    ],
    "graphql_cop": [
        {"flag": "-t", "description": "Target GraphQL endpoint URL", "required": True, "category": "target"},
        {"flag": "-o", "description": "Output file path", "default": True, "category": "output"},
        {"flag": "-f json", "description": "Output format", "default": True, "category": "output"},
    ],
    "jwt_tool": [
        {"flag": "-M at", "description": "Mode: run All Tests automatically", "default": True, "category": "mode"},
        {"flag": "-M pb", "description": "Mode: Playbook attack (targeted)", "default": False, "category": "mode"},
        {"flag": "-t", "description": "Target URL to test JWT against", "required": True, "category": "target"},
        {"flag": "-rh", "description": "Request header for JWT (e.g., Authorization: Bearer)", "default": "Authorization: Bearer", "category": "auth", "value_type": "string"},
        {"flag": "-cv", "description": "Expected valid response code", "default": "200", "category": "validation", "value_type": "string"},
        {"flag": "-C", "description": "Crack mode: attempt to brute-force HMAC secret", "default": False, "category": "attack"},
        {"flag": "-d", "description": "Dictionary file for cracking JWT secret", "required": False, "category": "attack"},
    ],
    "cors_scanner": [
        {"flag": "-u", "description": "Target URL to test CORS policy", "required": True, "category": "target"},
        {"flag": "-t", "description": "Template paths for CORS checks", "default": True, "category": "templates"},
        {"flag": "-json", "description": "Output in JSON format", "default": True, "category": "output"},
    ],
    "header_audit_tool": [
        {"flag": "-u", "description": "Target URL to audit security headers", "required": True, "category": "target"},
        {"flag": "-tags security-headers,misconfig", "description": "Template tags to use", "default": True, "category": "templates"},
        {"flag": "-severity", "description": "Severity filter", "default": "info,low,medium", "category": "filter", "value_type": "string"},
        {"flag": "-json", "description": "Output in JSON format", "default": True, "category": "output"},
    ],
}


# ═══════════════════════════════════════════════════════════════════════
#  Tool Catalog Endpoints
# ═══════════════════════════════════════════════════════════════════════

def _get_tool_catalog():
    """Import tool catalog lazily to avoid circular imports."""
    import sys
    import importlib.util

    # The tool registry lives in the worker-svc, we import it directly
    registry_path = "/home/kaal/Desktop/pentra/pentra_core/services/worker-svc/app/engine/tool_command_registry.py"
    try:
        if "tool_command_registry" not in sys.modules:
            spec = importlib.util.spec_from_file_location("tool_command_registry", registry_path)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules["tool_command_registry"] = mod
                spec.loader.exec_module(mod)
        return sys.modules["tool_command_registry"].TOOL_CATALOG
    except Exception as exc:
        logger.warning("Could not load tool registry: %s", exc)
        return {}


def _tool_to_api_response(tool_def, include_subcommands: bool = True) -> dict[str, Any]:
    """Convert a ToolDefinition to a JSON-friendly API response."""
    subcommands = TOOL_SUBCOMMANDS.get(tool_def.tool_id, [])
    phases = []
    for phase in tool_def.phases:
        phase_data = {
            "name": phase.name,
            "description": phase.description,
            "command_preview": " ".join(phase.command_template),
            "timeout_seconds": phase.timeout,
            "conditional": phase.condition is not None,
            "condition": phase.condition,
        }
        phases.append(phase_data)

    result = {
        "tool_id": tool_def.tool_id,
        "name": tool_def.name,
        "description": tool_def.description,
        "category": tool_def.category,
        "image": tool_def.image,
        "is_internal": tool_def.image == "internal",
        "attack_vectors": tool_def.attack_vectors,
        "phases": phases,
        "phase_count": len(tool_def.phases),
        "network_mode": tool_def.network_mode,
        "memory_limit": tool_def.memory_limit,
        "cpu_limit": tool_def.cpu_limit,
    }

    if include_subcommands:
        result["subcommands"] = subcommands
        result["subcommand_count"] = len(subcommands)

    return result


@router.get(
    "",
    summary="List all available tools",
    status_code=status.HTTP_200_OK,
)
async def list_tools(
    category: str | None = None,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
) -> dict[str, Any]:
    """List all security tools available in the Pentra engine.

    Each tool includes human-friendly descriptions, attack vectors covered,
    command phases, and available subcommands for customization.
    """
    catalog = _get_tool_catalog()

    tools = []
    categories: dict[str, int] = {}

    for tool_id, tool_def in catalog.items():
        cat = tool_def.category
        categories[cat] = categories.get(cat, 0) + 1
        if category and cat != category:
            continue
        tools.append(_tool_to_api_response(tool_def, include_subcommands=False))

    # Sort: recon first, then enum, vuln, verification, etc.
    category_order = {"scope_validation": 0, "recon": 1, "enum": 2, "vuln_scan": 3, "verification": 4, "ai_analysis": 5, "report_gen": 6}
    tools.sort(key=lambda t: (category_order.get(t["category"], 99), t["tool_id"]))

    return {
        "total": len(tools),
        "categories": categories,
        "tools": tools,
    }


@router.get(
    "/{tool_id}",
    summary="Get tool details with subcommands",
    status_code=status.HTTP_200_OK,
)
async def get_tool_detail(
    tool_id: str,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
) -> dict[str, Any]:
    """Get detailed information about a specific tool including full subcommand catalog."""
    catalog = _get_tool_catalog()
    tool_def = catalog.get(tool_id)
    if not tool_def:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool '{tool_id}' not found",
        )
    return _tool_to_api_response(tool_def, include_subcommands=True)


@router.get(
    "/{tool_id}/subcommands",
    summary="Get subcommand catalog for a tool",
    status_code=status.HTTP_200_OK,
)
async def get_tool_subcommands(
    tool_id: str,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
) -> dict[str, Any]:
    """Get the full subcommand catalog with human-friendly descriptions.

    Each subcommand includes:
    - ``flag``: the command-line flag
    - ``description``: what it does in plain English
    - ``default``: default value (if any)
    - ``category``: functional category (output, performance, scope, etc.)
    """
    catalog = _get_tool_catalog()
    if tool_id not in catalog:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool '{tool_id}' not found",
        )

    subcommands = TOOL_SUBCOMMANDS.get(tool_id, [])

    # Group by category
    by_category: dict[str, list] = {}
    for sc in subcommands:
        cat = sc.get("category", "other")
        by_category.setdefault(cat, []).append(sc)

    return {
        "tool_id": tool_id,
        "total": len(subcommands),
        "subcommands": subcommands,
        "by_category": by_category,
    }


@router.post(
    "/preview-command",
    summary="Preview rendered command for a tool+phase",
    status_code=status.HTTP_200_OK,
)
async def preview_command(
    body: dict,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
) -> dict[str, Any]:
    """Render a command preview for a specific tool and phase.

    Accepts ``tool_id``, ``phase`` name, and ``context`` variables
    (like base_url, target_host) to show the exact command that would run.
    """
    tool_id = body.get("tool_id", "")
    phase_name = body.get("phase", "")
    context = body.get("context", {})

    catalog = _get_tool_catalog()
    tool_def = catalog.get(tool_id)
    if not tool_def:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool '{tool_id}' not found",
        )

    for phase in tool_def.phases:
        if phase.name == phase_name:
            rendered = []
            for part in phase.command_template:
                try:
                    rendered.append(part.format(**context))
                except (KeyError, IndexError):
                    rendered.append(part)

            return {
                "tool_id": tool_id,
                "phase": phase_name,
                "command": rendered,
                "command_string": " ".join(rendered),
                "description": phase.description,
                "timeout_seconds": phase.timeout,
            }

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Phase '{phase_name}' not found for tool '{tool_id}'",
    )
