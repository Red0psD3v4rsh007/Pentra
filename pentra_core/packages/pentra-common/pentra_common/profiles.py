"""Shared scan profile definitions and config normalization helpers."""

from __future__ import annotations

from copy import deepcopy
import ipaddress
from typing import Any
from urllib.parse import urlparse

from pentra_common.config.settings import get_settings

DEFAULT_EXTERNAL_WEB_API_PROFILE_ID = "external_web_api_v1"
_WEB_API_ASSET_TYPES = {"web_app", "api"}
_SAFE_LIVE_TOOLS = {
    "httpx_probe",
    "ffuf",
    "nuclei",
    "sqlmap",
    "sqlmap_verify",
    "custom_poc",
    "web_interact",
}


def prepare_scan_config(
    *,
    scan_type: str,
    asset_type: str,
    asset_target: str,
    config: dict[str, Any] | None,
) -> dict[str, Any]:
    """Normalize scan config and apply a default profile when appropriate."""
    normalized = deepcopy(config or {})
    profile_value = normalized.get("profile")
    profile_meta = profile_value if isinstance(profile_value, dict) else {}

    if asset_type not in _WEB_API_ASSET_TYPES or scan_type == "exploit_verify":
        return normalized

    profile_id = str(
        normalized.get("profile_id")
        or profile_meta.get("id")
        or DEFAULT_EXTERNAL_WEB_API_PROFILE_ID
    )

    if isinstance(profile_value, str):
        # Frontend scan creation uses lightweight values like "recon"/"full" to describe
        # the selected UI profile. Those are not the canonical web/API profile ids and
        # should not overwrite the rich external profile object that downstream workers use.
        normalized.setdefault("requested_scan_profile", profile_value)
        if profile_id == profile_value:
            profile_id = DEFAULT_EXTERNAL_WEB_API_PROFILE_ID
        normalized.pop("profile", None)

    if profile_id != DEFAULT_EXTERNAL_WEB_API_PROFILE_ID:
        normalized.setdefault("profile_id", profile_id)
        return normalized

    base = external_web_api_profile(asset_type=asset_type, target=asset_target)
    merged = _deep_merge(base, normalized)
    merged["profile_id"] = DEFAULT_EXTERNAL_WEB_API_PROFILE_ID
    merged["profile"] = {
        **merged.get("profile", {}),
        "id": DEFAULT_EXTERNAL_WEB_API_PROFILE_ID,
    }
    return merged


def enforce_safe_scan_config(
    *,
    scan_type: str,
    asset_type: str,
    asset_target: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Validate that the normalized scan config stays within safe runtime bounds."""
    settings = get_settings()
    normalized = deepcopy(config)
    target_context = derive_target_context(asset_type=asset_type, target=asset_target)
    asset_host = target_context["host"]
    asset_domain = target_context["scope_domain"]

    scope = normalized.get("scope", {}) if isinstance(normalized.get("scope"), dict) else {}
    scope_target = str(scope.get("target") or asset_target).strip()
    if scope_target != str(asset_target).strip():
        raise ValueError("Scan scope target must match the selected asset target")

    max_depth = int(scope.get("max_depth", settings.max_scan_depth))
    max_subdomains = int(scope.get("max_subdomains", settings.max_scan_subdomains))
    max_endpoints = int(scope.get("max_endpoints", settings.max_scan_endpoints))
    if max_depth > settings.max_scan_depth:
        raise ValueError(f"max_depth exceeds safe limit ({settings.max_scan_depth})")
    if max_subdomains > settings.max_scan_subdomains:
        raise ValueError(
            f"max_subdomains exceeds safe limit ({settings.max_scan_subdomains})"
        )
    if max_endpoints > settings.max_scan_endpoints:
        raise ValueError(
            f"max_endpoints exceeds safe limit ({settings.max_scan_endpoints})"
        )

    allowed_hosts = _normalize_string_list(scope.get("allowed_hosts"))
    allowed_domains = _normalize_string_list(scope.get("allowed_domains"))
    allowed_cidrs = _normalize_string_list(scope.get("allowed_cidrs"))

    if len(allowed_hosts) > settings.max_scope_hosts:
        raise ValueError(f"allowed_hosts exceeds safe limit ({settings.max_scope_hosts})")
    if len(allowed_cidrs) > settings.max_scope_cidrs:
        raise ValueError(f"allowed_cidrs exceeds safe limit ({settings.max_scope_cidrs})")

    for host in allowed_hosts:
        if not _host_within_asset_scope(host, asset_host=asset_host, asset_domain=asset_domain):
            raise ValueError(f"allowed_hosts contains out-of-scope host: {host}")

    for domain in allowed_domains:
        if not _domain_within_asset_scope(
            domain, asset_host=asset_host, asset_domain=asset_domain
        ):
            raise ValueError(f"allowed_domains contains out-of-scope domain: {domain}")

    for cidr in allowed_cidrs:
        if not _cidr_within_asset_scope(cidr, asset_host=asset_host):
            raise ValueError(f"allowed_cidrs contains out-of-scope network: {cidr}")

    rate_limits = (
        normalized.get("rate_limits", {})
        if isinstance(normalized.get("rate_limits"), dict)
        else {}
    )
    _enforce_limit(
        rate_limits,
        key="http_requests_per_minute",
        safe_limit=settings.max_http_requests_per_minute,
    )
    _enforce_limit(
        rate_limits,
        key="ffuf_requests_per_minute",
        safe_limit=settings.max_ffuf_requests_per_minute,
    )
    _enforce_limit(
        rate_limits,
        key="nuclei_requests_per_minute",
        safe_limit=settings.max_nuclei_requests_per_minute,
    )
    _enforce_limit(
        rate_limits,
        key="sqlmap_threads",
        safe_limit=settings.max_sqlmap_threads,
    )
    _enforce_limit(
        rate_limits,
        key="zap_minutes",
        safe_limit=settings.max_zap_minutes,
    )

    execution = (
        normalized.get("execution", {})
        if isinstance(normalized.get("execution"), dict)
        else {}
    )
    live_tools = _normalize_string_list(execution.get("allowed_live_tools"))
    unknown_tools = sorted(set(live_tools) - _SAFE_LIVE_TOOLS)
    if unknown_tools:
        raise ValueError(
            "allowed_live_tools contains unsupported entries: "
            + ", ".join(unknown_tools)
        )

    if execution.get("target_policy") == "local_only" and not _is_local_asset_host(asset_host):
        raise ValueError("local_only execution policy can only be used with loopback/private targets")

    verification_policy = (
        normalized.get("verification_policy", {})
        if isinstance(normalized.get("verification_policy"), dict)
        else {}
    )
    if int(
        verification_policy.get("max_dynamic_nodes_per_scan", settings.max_dynamic_nodes_per_scan)
    ) > settings.max_dynamic_nodes_per_scan:
        raise ValueError(
            "verification max_dynamic_nodes_per_scan exceeds safe limit"
        )
    if int(
        verification_policy.get("max_verifications_per_type", settings.max_verifications_per_type)
    ) > settings.max_verifications_per_type:
        raise ValueError(
            "verification max_verifications_per_type exceeds safe limit"
        )

    stateful = (
        normalized.get("stateful_testing", {})
        if isinstance(normalized.get("stateful_testing"), dict)
        else {}
    )
    if int(stateful.get("max_pages", settings.max_stateful_pages)) > settings.max_stateful_pages:
        raise ValueError(f"stateful max_pages exceeds safe limit ({settings.max_stateful_pages})")
    if int(stateful.get("max_replays", settings.max_stateful_replays)) > settings.max_stateful_replays:
        raise ValueError(
            f"stateful max_replays exceeds safe limit ({settings.max_stateful_replays})"
        )

    return normalized


def external_web_api_profile(*, asset_type: str, target: str) -> dict[str, Any]:
    """Return the canonical External Web + API v1 profile."""
    context = derive_target_context(asset_type=asset_type, target=target)
    base_url = context["base_url"]
    host = context["host"]
    scope_domain = context["scope_domain"]
    allowed_hosts = [host] if host else []
    allowed_domains = [scope_domain] if scope_domain and scope_domain != host else []

    http_rpm = 120
    ffuf_rpm = 60
    nuclei_rpm = 35
    zap_minutes = 3
    max_subdomains = 25
    max_endpoints = 60
    content_paths = [
        "graphql",
        "openapi.json",
        "api/v1/auth/login",
        "api/v1/users/2",
        "internal/debug",
    ]
    http_probe_paths = ["/", "/graphql", "/openapi.json"]

    return {
        "profile_id": DEFAULT_EXTERNAL_WEB_API_PROFILE_ID,
        "profile": {
            "id": DEFAULT_EXTERNAL_WEB_API_PROFILE_ID,
            "name": "External Web + API v1",
            "category": "external_web_api",
            "description": (
                "Focused external assessment for public web applications and APIs with "
                "subdomain discovery, HTTP probing, technology fingerprinting, "
                "selected content discovery, and targeted vulnerability checks."
            ),
        },
        "targeting": {
            "asset_type": asset_type,
            "target": target,
            "base_url": base_url,
            "host": host,
            "scope_domain": scope_domain,
        },
        "scope": {
            "target": target,
            "allowed_hosts": allowed_hosts,
            "allowed_domains": allowed_domains,
            "allowed_cidrs": [],
            "include_subdomains": True,
            "max_subdomains": max_subdomains,
            "max_endpoints": max_endpoints,
            "max_depth": 2,
        },
        "rate_limits": {
            "http_requests_per_minute": http_rpm,
            "ffuf_requests_per_minute": ffuf_rpm,
            "nuclei_requests_per_minute": nuclei_rpm,
            "zap_minutes": zap_minutes,
            "sqlmap_threads": 1,
        },
        "execution": {
            "mode": "controlled_live_local",
            "target_policy": "local_only",
            "allowed_live_tools": [
                "scope_check",
                "httpx_probe",
                "ffuf",
                "nuclei",
                "sqlmap",
                "sqlmap_verify",
                "custom_poc",
                "web_interact",
            ],
        },
        "verification_policy": {
            "enabled": True,
            "mode": "safe_first",
            "allowed_vulnerability_types": ["sql_injection", "idor"],
            "allowed_tools": ["sqlmap_verify", "custom_poc"],
            "blocked_vulnerability_types": [
                "rce",
                "command_injection",
                "auth_bypass",
                "default_credentials",
                "ssrf",
                "lfi",
                "xss",
            ],
            "max_dynamic_nodes_per_scan": 4,
            "max_verifications_per_type": 1,
            "target_policy": "local_only",
            "proof_requirements": {
                "sql_injection": ["injectable_parameter", "database_confirmation"],
                "idor": ["unauthorized_object_read", "sensitive_field_exposure"],
            },
            "request_budget": {
                "sqlmap_verify": 60,
                "custom_poc": 2,
            },
            "deny_actions": [
                "no persistence",
                "no destructive modification",
                "no reverse shells",
                "no out-of-scope targets",
            ],
        },
        "selected_checks": {
            "subdomain_discovery": True,
            "http_probing": True,
            "technology_fingerprinting": True,
            "directory_discovery": True,
            "http_probe_paths": http_probe_paths,
            "content_paths": content_paths,
            "nuclei_tags": [
                "exposure",
                "misconfig",
                "sqli",
                "idor",
                "auth-bypass",
                "deserialization",
                "swagger",
                "graphql",
                "cors",
                "api",
            ],
            "api_checks": [
                "openapi-exposure",
                "graphql-introspection",
                "idor",
                "sql-injection",
                "deserialization",
            ],
            "sqlmap": {
                "method": "GET",
                "path": "/api/v1/auth/login?username=admin&password=admin123",
                "ignore_codes": [401],
                "risk": 2,
                "level": 3,
            },
            "authenticated_crawling": True,
            "workflow_replay": True,
            "stateful_testing": True,
        },
        "stateful_testing": {
            "enabled": True,
            "crawl_max_depth": 2,
            "max_pages": 18,
            "max_replays": 4,
            "seed_paths": [
                "/",
                "/login",
                "/portal/dashboard",
                "/portal/checkout/cart",
            ],
            "default_csrf_token": "demo-csrf",
            "auth": {
                "login_page_path": "/login",
                "username_field": "username",
                "password_field": "password",
                "success_path_contains": "/portal/dashboard",
                "credentials": [],
            },
        },
        "deterministic_mode": True,
        "toolchain": [
            {"phase": "scope_validation", "tool": "scope_check"},
            {"phase": "recon", "tool": "subfinder"},
            {"phase": "recon", "tool": "amass"},
            {"phase": "recon", "tool": "nmap_discovery"},
            {"phase": "enum", "tool": "httpx_probe"},
            {"phase": "enum", "tool": "web_interact"},
            {"phase": "enum", "tool": "nmap_svc"},
            {"phase": "enum", "tool": "ffuf"},
            {"phase": "vuln_scan", "tool": "nuclei"},
            {"phase": "vuln_scan", "tool": "zap"},
            {"phase": "vuln_scan", "tool": "sqlmap"},
        ],
        "command_context": {
            "base_url": base_url,
            "target_host": host,
            "scope_host": scope_domain or host,
            "http_rate_limit": http_rpm,
            "ffuf_rate_limit": ffuf_rpm,
            "nuclei_rate_limit": nuclei_rpm,
            "nuclei_tags": ",".join(
                [
                    "exposure",
                    "misconfig",
                    "sqli",
                    "idor",
                    "auth-bypass",
                    "deserialization",
                    "swagger",
                    "graphql",
                    "cors",
                    "api",
                ]
            ),
            "ffuf_extensions": "json,txt,php,html,js",
            "zap_minutes": zap_minutes,
            "max_subdomains": max_subdomains,
            "max_endpoints": max_endpoints,
            "sqlmap_threads": 1,
        },
    }


def derive_target_context(*, asset_type: str, target: str) -> dict[str, str]:
    """Return normalized host and base URL details for a scan target."""
    raw = str(target or "").strip()
    if not raw:
        return {
            "scheme": "https",
            "host": "",
            "base_url": "",
            "scope_domain": "",
            "asset_type": asset_type,
        }

    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    scheme = parsed.scheme or "https"
    host = parsed.hostname or raw.split("/", 1)[0]
    netloc = parsed.netloc or host
    base_url = f"{scheme}://{netloc}".rstrip("/")

    return {
        "scheme": scheme,
        "host": host,
        "base_url": base_url,
        "scope_domain": _scope_domain(host),
        "asset_type": asset_type,
    }


def _scope_domain(host: str) -> str:
    host = host.strip().lower()
    if not host:
        return ""
    if host == "localhost":
        return host
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)

    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = deepcopy(value)

    return merged


def _normalize_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _host_within_asset_scope(host: str, *, asset_host: str, asset_domain: str) -> bool:
    candidate = host.strip().lower()
    if not candidate:
        return True
    if candidate == asset_host.lower():
        return True
    if asset_domain and candidate == asset_domain.lower():
        return True
    return bool(asset_domain and candidate.endswith(f".{asset_domain.lower()}"))


def _domain_within_asset_scope(domain: str, *, asset_host: str, asset_domain: str) -> bool:
    candidate = domain.strip().lower()
    if not candidate:
        return True
    if candidate in {asset_host.lower(), asset_domain.lower()}:
        return True
    return bool(asset_domain and candidate.endswith(f".{asset_domain.lower()}"))


def _cidr_within_asset_scope(cidr: str, *, asset_host: str) -> bool:
    try:
        host_ip = ipaddress.ip_address(asset_host)
        return host_ip in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        # Domain-scoped assets should not introduce raw CIDRs.
        return False


def _enforce_limit(config: dict[str, Any], *, key: str, safe_limit: int) -> None:
    if key not in config:
        return

    value = int(config[key])
    if value > safe_limit:
        raise ValueError(f"{key} exceeds safe limit ({safe_limit})")


def _is_local_asset_host(host: str) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True

    try:
        return ipaddress.ip_address(host).is_loopback or ipaddress.ip_address(host).is_private
    except ValueError:
        return False
