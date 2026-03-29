"""Credential injector — maps scan.config.credentials to tool-specific command flags.

For each tool in the registry, injects authentication into the command:
  - nuclei:    -H "Cookie: ..." or -H "Authorization: Bearer ..."
  - sqlmap:    --cookie="..." or --auth-type=basic --auth-cred="user:pass"
  - ffuf:      -H "Cookie: ..." or -H "Authorization: ..."
  - httpx:     -H "Cookie: ..."
  - zap:       context-based auth injection
  - nmap:      (N/A — network layer, no auth)
  - subfinder: (N/A — passive recon)
  - amass:     (N/A — passive recon)
  - custom_poc: injects Cookie/Auth header in HTTP request

Credential types from scan.config:
  {
    "credentials": {
      "type": "cookie" | "basic" | "bearer" | "oauth2" | "session_file",
      "cookie": "SESSIONID=abc123",
      "username": "admin",
      "password": "pass123",
      "token": "eyJhbG...",
      "client_id": "...",
      "client_secret": "...",
      "token_url": "...",
      "session_file_path": "/path/to/session"
    }
  }
"""

from __future__ import annotations

import base64
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Sentinel for redacting credentials in logs
_REDACTED = "[REDACTED]"

# Tools that accept no auth (network/passive recon/SAST)
_NO_AUTH_TOOLS = frozenset({
    "scope_check", "subfinder", "amass", "nmap_discovery", "nmap_svc",
    "tech_detect", "report_gen", "ai_triage",
    "git_clone", "semgrep", "trufflehog", "dependency_audit", "api_spec_parser",
})

# Tool-specific injection maps
# Each tool maps credential_type → list of flag templates
_TOOL_AUTH_FLAGS: dict[str, dict[str, list[str]]] = {
    "nuclei": {
        "cookie": ["-H", "Cookie: {cookie}"],
        "basic": ["-H", "Authorization: Basic {basic_b64}"],
        "bearer": ["-H", "Authorization: Bearer {token}"],
        "oauth2": ["-H", "Authorization: Bearer {token}"],
    },
    "sqlmap": {
        "cookie": ["--cookie={cookie}"],
        "basic": ["--auth-type=basic", "--auth-cred={username}:{password}"],
        "bearer": ["--header=Authorization: Bearer {token}"],
        "oauth2": ["--header=Authorization: Bearer {token}"],
    },
    "ffuf": {
        "cookie": ["-H", "Cookie: {cookie}"],
        "basic": ["-H", "Authorization: Basic {basic_b64}"],
        "bearer": ["-H", "Authorization: Bearer {token}"],
        "oauth2": ["-H", "Authorization: Bearer {token}"],
    },
    "httpx_probe": {
        "cookie": ["-H", "Cookie: {cookie}"],
        "basic": ["-H", "Authorization: Basic {basic_b64}"],
        "bearer": ["-H", "Authorization: Bearer {token}"],
        "oauth2": ["-H", "Authorization: Bearer {token}"],
    },
    "zap": {
        "cookie": ["-config", "spider.cookie={cookie}", "-config", "request.header.Cookie={cookie}"],
        "basic": ["-config", "connection.httpState.credentials.auth.basic.user={username}",
                  "-config", "connection.httpState.credentials.auth.basic.pass={password}"],
        "bearer": ["-config", "request.header.Authorization=Bearer {token}"],
        "oauth2": ["-config", "request.header.Authorization=Bearer {token}"],
    },
    "nikto": {
        "cookie": ["-C", "{cookie}"],
        "basic": ["-id", "{username}:{password}"],
        "bearer": ["-H", "Authorization: Bearer {token}"],
    },
    "dalfox": {
        "cookie": ["-C", "{cookie}"],
        "basic": ["-H", "Authorization: Basic {basic_b64}"],
        "bearer": ["-H", "Authorization: Bearer {token}"],
    },
    "custom_poc": {
        "cookie": ["-H", "Cookie: {cookie}"],
        "basic": ["-H", "Authorization: Basic {basic_b64}"],
        "bearer": ["-H", "Authorization: Bearer {token}"],
        "oauth2": ["-H", "Authorization: Bearer {token}"],
    },
    "web_interact": {
        "cookie": ["-H", "Cookie: {cookie}"],
        "basic": ["-H", "Authorization: Basic {basic_b64}"],
        "bearer": ["-H", "Authorization: Bearer {token}"],
    },
    "graphql_cop": {
        "cookie": ["-H", "{{\"Cookie\":\"{cookie}\"}}"],
        "bearer": ["-H", "{{\"Authorization\":\"Bearer {token}\"}}"],
    },
    "jwt_tool": {
        "cookie": ["-C", "{cookie}"],
        "bearer": ["-t", "{token}"],
    },
    "cors_scanner": {
        "cookie": ["-H", "Cookie: {cookie}"],
        "bearer": ["-H", "Authorization: Bearer {token}"],
    },
    "header_audit_tool": {
        "cookie": ["-H", "Cookie: {cookie}"],
        "bearer": ["-H", "Authorization: Bearer {token}"],
    },
    "cors_check": {
        "cookie": ["-H", "Cookie: {cookie}"],
        "bearer": ["-H", "Authorization: Bearer {token}"],
    },
    "header_audit": {
        "cookie": ["-H", "Cookie: {cookie}"],
        "bearer": ["-H", "Authorization: Bearer {token}"],
    },
    "sqlmap_verify": {
        "cookie": ["--cookie={cookie}"],
        "basic": ["--auth-type=basic", "--auth-cred={username}:{password}"],
        "bearer": ["--header=Authorization: Bearer {token}"],
    },
    "metasploit": {
        "cookie": [],  # Metasploit uses module-specific options, handled via config
        "basic": [],
        "bearer": [],
    },
}


def inject_credentials(
    tool_name: str,
    command: list[str],
    credentials: dict[str, Any],
) -> list[str]:
    """Append auth flags to the tool command based on credential type.

    Args:
        tool_name: The tool being executed (e.g., "nuclei", "sqlmap")
        command: The existing command list to extend
        credentials: The scan.config.credentials dict

    Returns:
        New command list with auth flags appended.
        Original command is returned unmodified if no credentials or tool doesn't use auth.
    """
    if not credentials:
        return command

    # Skip tools that don't accept auth
    if tool_name in _NO_AUTH_TOOLS:
        return command

    cred_type = str(credentials.get("type", "")).strip().lower()
    if not cred_type:
        return command

    # Look up tool-specific flags
    tool_flags = _TOOL_AUTH_FLAGS.get(tool_name)
    if not tool_flags:
        logger.debug("No auth flag mapping for tool %s — skipping injection", tool_name)
        return command

    templates = tool_flags.get(cred_type)
    if not templates:
        logger.debug("No %s auth mapping for tool %s — skipping", cred_type, tool_name)
        return command

    # Build context for template rendering
    context = _build_credential_context(credentials)

    # Render templates
    rendered_flags: list[str] = []
    for template in templates:
        try:
            rendered = template.format(**context)
            rendered_flags.append(rendered)
        except (KeyError, IndexError) as exc:
            logger.warning(
                "Failed to render credential flag for %s: %s (template=%s)",
                tool_name, exc, template,
            )
            continue

    if rendered_flags:
        logger.info(
            "Injected %s credentials into %s command (%d flags)",
            cred_type, tool_name, len(rendered_flags),
        )

    return command + rendered_flags


def _build_credential_context(credentials: dict[str, Any]) -> dict[str, str]:
    """Build the template rendering context from raw credentials."""
    username = str(credentials.get("username", "")).strip()
    password = str(credentials.get("password", "")).strip()
    cookie = str(credentials.get("cookie", "")).strip()
    token = str(credentials.get("token", "")).strip()

    # Compute base64 for Basic auth
    basic_b64 = ""
    if username and password:
        basic_b64 = base64.b64encode(f"{username}:{password}".encode()).decode()

    return {
        "cookie": cookie,
        "username": username,
        "password": password,
        "token": token,
        "basic_b64": basic_b64,
        "client_id": str(credentials.get("client_id", "")).strip(),
        "client_secret": str(credentials.get("client_secret", "")).strip(),
        "token_url": str(credentials.get("token_url", "")).strip(),
    }


def get_credential_env_vars(credentials: dict[str, Any]) -> dict[str, str]:
    """Return environment variables for tools that read auth from env.

    These are set in the Docker container environment.
    Useful for tools that don't support CLI flags for auth.
    """
    if not credentials:
        return {}

    env: dict[str, str] = {}
    cred_type = str(credentials.get("type", "")).strip().lower()

    if cred_type == "cookie":
        env["PENTRA_AUTH_COOKIE"] = str(credentials.get("cookie", ""))
    elif cred_type == "basic":
        env["PENTRA_AUTH_USERNAME"] = str(credentials.get("username", ""))
        env["PENTRA_AUTH_PASSWORD"] = str(credentials.get("password", ""))
    elif cred_type == "bearer":
        env["PENTRA_AUTH_TOKEN"] = str(credentials.get("token", ""))
    elif cred_type == "oauth2":
        env["PENTRA_AUTH_TOKEN"] = str(credentials.get("token", ""))
        env["PENTRA_AUTH_CLIENT_ID"] = str(credentials.get("client_id", ""))
        env["PENTRA_AUTH_CLIENT_SECRET"] = str(credentials.get("client_secret", ""))
        env["PENTRA_AUTH_TOKEN_URL"] = str(credentials.get("token_url", ""))

    return env


def redact_command_for_logging(command: list[str]) -> list[str]:
    """Return a copy of the command with sensitive values redacted.

    Used for writing to tool execution logs so credentials
    are never exposed in plaintext.
    """
    redacted = []
    skip_next = False

    sensitive_prefixes = (
        "Cookie:", "Authorization:", "Bearer ",
        "--cookie=", "--auth-cred=",
    )
    sensitive_flags = frozenset({"-C", "-t", "--cookie", "--auth-cred", "-id"})

    for i, part in enumerate(command):
        if skip_next:
            redacted.append(_REDACTED)
            skip_next = False
            continue

        # Check if this is a value following a sensitive flag
        if any(part.startswith(prefix) for prefix in sensitive_prefixes):
            redacted.append(part.split("=")[0] + "=" + _REDACTED if "=" in part else _REDACTED)
        elif part in sensitive_flags:
            redacted.append(part)
            skip_next = True
        elif part in ("-H",) and i + 1 < len(command):
            # Check if the next argument is a sensitive header
            next_part = command[i + 1] if i + 1 < len(command) else ""
            if any(next_part.startswith(p) for p in ("Cookie:", "Authorization:")):
                redacted.append(part)
                skip_next = True
            else:
                redacted.append(part)
        else:
            redacted.append(part)

    return redacted
