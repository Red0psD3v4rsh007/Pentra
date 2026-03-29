"""Shared scan profile definitions and config normalization helpers."""

from __future__ import annotations

from copy import deepcopy
import ipaddress
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from pentra_common.config.settings import get_settings
from pentra_common.schemas.target_profile import (
    TargetProfileCatalog,
    TargetProfileHypothesis,
)

DEFAULT_EXTERNAL_WEB_API_PROFILE_ID = "external_web_api_v1"
FIELD_VALIDATION_EXTERNAL_WEB_API_PROFILE_ID = "external_web_api_field_validation_v1"
_WEB_API_ASSET_TYPES = {"web_app", "api"}
_SAFE_LIVE_TOOLS = {
    "scope_check",
    "httpx_probe",
    "ffuf",
    "nuclei",
    "zap",
    "sqlmap",
    "sqlmap_verify",
    "custom_poc",
    "web_interact",
    "dalfox",
    "graphql_cop",
    "jwt_tool",
    "cors_scanner",
    "amass",
    "subfinder",
    "nmap_discovery",
    "nmap_svc",
    "nikto",
    "git_clone",
    "semgrep",
    "trufflehog",
    "dependency_audit",
    "api_spec_parser",
}
_DERIVED_TOOLS = {"ai_triage", "report_gen"}
_PRODUCT_UNSUPPORTED_TOOLS: list[str] = []
_EXTERNAL_WEB_API_AUTO_LIVE_TOOLS = [
    "scope_check",
    "subfinder",
    "amass",
    "nmap_discovery",
    "httpx_probe",
    "web_interact",
    "nmap_svc",
    "ffuf",
    "nuclei",
    "zap",
    "sqlmap",
    "nikto",
    "dalfox",
    "graphql_cop",
    "jwt_tool",
    "cors_scanner",
    "sqlmap_verify",
    "custom_poc",
]
_FIELD_VALIDATION_AUTO_LIVE_TOOLS = list(_EXTERNAL_WEB_API_AUTO_LIVE_TOOLS)
_FIELD_VALIDATION_APPROVAL_REQUIRED_TOOLS: list[str] = []
_PENTRA_CORE_DIR = Path(__file__).resolve().parents[3]
_TARGET_PROFILE_PATH = _PENTRA_CORE_DIR / "knowledge" / "target_profiles.yaml"
_GENERIC_HTTP_PROBE_PATHS = ["/", "/login", "/graphql", "/openapi.json", "/swagger.json"]
_GENERIC_CONTENT_PATHS = [
    "login",
    "api",
    "graphql",
    "openapi.json",
    "swagger.json",
    "swagger",
    "admin",
    ".well-known/security.txt",
]
_PROFILE_CATALOG: dict[str, dict[str, Any]] = {
    "recon": {
        "name": "Recon Sweep",
        "description": (
            "Product-safe live recon for scoped web and API targets using scope validation "
            "and HTTP probing only."
        ),
        "duration": "~3 min",
        "priority": "normal",
    },
    "vuln": {
        "name": "Vulnerability Assessment",
        "description": (
            "Controlled live enumeration and vulnerability scanning for web/API targets "
            "with explicit scope enforcement."
        ),
        "duration": "~10 min",
        "priority": "normal",
    },
    "full": {
        "name": "Full Assessment",
        "description": (
            "Controlled live web/API assessment with safe verification, AI triage, "
            "and report generation."
        ),
        "duration": "~20 min",
        "priority": "high",
    },
}
_PROFILE_VARIANTS: dict[str, dict[str, Any]] = {
    DEFAULT_EXTERNAL_WEB_API_PROFILE_ID: {
        "variant": "standard",
        "requires_preflight": False,
        "catalog": {},
    },
    FIELD_VALIDATION_EXTERNAL_WEB_API_PROFILE_ID: {
        "variant": "field_validation",
        "requires_preflight": True,
        "catalog": {
            "full": {
                "name": "Field Validation",
                "description": (
                    "Authorized external-target field validation with bounded live replay, "
                    "aggressive demotion, and proof-first verification lanes."
                ),
                "duration": "~15 min",
                "priority": "high",
            }
        },
    },
}


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


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

    base = _profile_base_for_id(
        profile_id=profile_id,
        asset_type=asset_type,
        target=asset_target,
        scan_type=scan_type,
    )
    if base is None:
        normalized.setdefault("profile_id", profile_id)
        return normalized

    merged = _deep_merge(base, normalized)
    merged["profile_id"] = profile_id
    merged["profile"] = {
        **merged.get("profile", {}),
        "id": profile_id,
    }
    merged["execution_contract"] = build_scan_profile_contract(
        scan_type=scan_type,
        asset_type=asset_type,
        target=asset_target,
        config=merged,
    )
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
    execution_mode = str(execution.get("mode") or "").strip().lower()
    if execution_mode == "demo_simulated" and not settings.allow_demo_simulated_scans:
        raise ValueError("demo_simulated mode is disabled for product scans")

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


def external_web_api_profile(
    *,
    asset_type: str,
    target: str,
    scan_type: str,
) -> dict[str, Any]:
    """Return the canonical External Web + API v1 profile."""
    context = derive_target_context(asset_type=asset_type, target=target)
    base_url = context["base_url"]
    host = context["host"]
    scope_domain = context["scope_domain"]
    allowed_hosts = [host] if host else []
    allowed_domains = [scope_domain] if scope_domain and scope_domain != host else []
    local_target = _is_local_asset_host(host)
    execution_mode = (
        "controlled_live_local" if local_target else "controlled_live_external"
    )
    target_policy = "local_only" if local_target else "external_authorized"

    http_rpm = 120
    ffuf_rpm = 60
    nuclei_rpm = 35
    zap_minutes = 3
    max_subdomains = 25
    max_endpoints = 60
    content_paths = list(_GENERIC_CONTENT_PATHS)
    http_probe_paths = list(_GENERIC_HTTP_PROBE_PATHS)
    sqlmap_path = "/"

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
            "mode": execution_mode,
            "target_policy": target_policy,
            "allowed_live_tools": [
                *_EXTERNAL_WEB_API_AUTO_LIVE_TOOLS,
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
                "path": sqlmap_path,
                "ignore_codes": [401],
                "risk": 2,
                "level": 3,
            },
            "authenticated_crawling": False,
            "workflow_replay": False,
            "stateful_testing": False,
        },
        "stateful_testing": {
            "enabled": False,
            "crawl_max_depth": 2,
            "max_pages": 18,
            "max_replays": 4,
            "seed_paths": ["/"],
            "default_csrf_token": "pentra-safe",
            "auth": {
                "login_page_path": "/login",
                "username_field": "username",
                "password_field": "password",
                "success_path_contains": "",
                "credentials": [],
            },
        },
        "benchmark_inputs_enabled": False,
        "deterministic_mode": True,
        "toolchain": _external_web_api_toolchain(scan_type, config=None),
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


def external_web_api_field_validation_profile(
    *,
    asset_type: str,
    target: str,
    scan_type: str,
) -> dict[str, Any]:
    """Return the field-validation profile for authorized real-target work."""
    base = external_web_api_profile(
        asset_type=asset_type,
        target=target,
        scan_type=scan_type,
    )
    target_policy = str(base["execution"].get("target_policy") or "local_only")
    base["profile_id"] = FIELD_VALIDATION_EXTERNAL_WEB_API_PROFILE_ID
    base["profile"] = {
        "id": FIELD_VALIDATION_EXTERNAL_WEB_API_PROFILE_ID,
        "name": "Field Validation",
        "category": "authorized_real_target_validation",
        "description": (
            "Authorized real-target field validation emphasizing proof-ready replay, "
            "tight rate limits, and aggressive demotion when evidence stays weak."
        ),
    }
    base["scope"]["max_endpoints"] = 25
    base["scope"]["max_depth"] = 2
    base["rate_limits"].update(
        {
            "http_requests_per_minute": 90,
            "ffuf_requests_per_minute": 30,
            "nuclei_requests_per_minute": 20,
            "zap_minutes": 3,
            "sqlmap_threads": 1,
        }
    )
    base["execution"]["allowed_live_tools"] = list(_FIELD_VALIDATION_AUTO_LIVE_TOOLS)
    base["execution"]["approval_required_tools"] = []
    base["verification_policy"].update(
        {
            "allowed_vulnerability_types": [
                "sql_injection",
                "idor",
                "browser_xss",
                "graphql_introspection",
                "openapi_exposure",
                "stack_trace_exposure",
            ],
            "allowed_tools": ["sqlmap_verify", "custom_poc", "web_interact"],
            "blocked_vulnerability_types": [
                "rce",
                "command_injection",
                "auth_bypass",
                "default_credentials",
                "ssrf",
                "lfi",
            ],
            "max_dynamic_nodes_per_scan": 3,
            "max_verifications_per_type": 2,
            "target_policy": target_policy,
            "proof_requirements": {
                "sql_injection": ["injectable_parameter", "database_confirmation"],
                "idor": ["unauthorized_object_read", "sensitive_field_exposure"],
                "browser_xss": ["browser_execution_canary"],
                "graphql_introspection": ["schema_disclosure"],
                "openapi_exposure": ["public_api_schema"],
                "stack_trace_exposure": ["stack_trace_truth"],
            },
            "request_budget": {
                "sqlmap_verify": 40,
                "custom_poc": 3,
                "web_interact": 6,
            },
            "deny_actions": [
                "no destructive modification",
                "no persistence",
                "no credential stuffing",
                "no out-of-scope hosts",
                "no high-volume brute force",
            ],
        }
    )
    http_probe_paths = _field_validation_http_probe_paths(
        asset_type=asset_type,
        target=target,
    )
    content_paths = _field_validation_content_paths(
        asset_type=asset_type,
        target=target,
    )
    base["selected_checks"].update(
        {
            "subdomain_discovery": True,
            "directory_discovery": True,
            "http_probe_paths": http_probe_paths,
            "content_paths": content_paths,
            "authenticated_crawling": True,
            "workflow_replay": True,
            "stateful_testing": True,
            "sqlmap": {
                "method": "GET",
                "path": "/",
                "ignore_codes": [401],
                "risk": 1,
                "level": 2,
            },
        }
    )
    base["stateful_testing"].update(
        {
            "enabled": True,
            "crawl_max_depth": 2,
            "max_pages": 10,
            "max_replays": 3,
        }
    )
    base["benchmark_inputs_enabled"] = False
    return base


def _field_validation_http_probe_paths(*, asset_type: str, target: str) -> list[str]:
    normalized_asset_type = str(asset_type or "").strip().lower()
    normalized_target = str(target or "").strip().lower()
    paths = ["/"]

    if normalized_asset_type == "web_app" or any(
        marker in normalized_target for marker in ("login", "signin", "account")
    ):
        paths.append("/login")

    if normalized_asset_type == "api" or "graphql" in normalized_target:
        paths.extend(["/graphql", "/openapi.json", "/swagger.json"])
    elif any(marker in normalized_target for marker in ("openapi", "swagger")):
        paths.extend(["/openapi.json", "/swagger.json"])

    return _dedupe_strings(paths)


def _field_validation_content_paths(*, asset_type: str, target: str) -> list[str]:
    normalized_asset_type = str(asset_type or "").strip().lower()
    normalized_target = str(target or "").strip().lower()
    paths = ["admin"]

    if normalized_asset_type == "web_app" or any(
        marker in normalized_target for marker in ("login", "signin", "account")
    ):
        paths.append("login")

    if normalized_asset_type == "api" or "graphql" in normalized_target:
        paths.extend(["graphql", "openapi.json", "swagger.json"])
    elif any(marker in normalized_target for marker in ("openapi", "swagger")):
        paths.extend(["openapi.json", "swagger.json"])

    return _dedupe_strings(paths)


def list_scan_profile_contracts(*, asset_type: str, target: str) -> list[dict[str, Any]]:
    """Return the honest product-safe profile catalog for an asset target."""
    if asset_type not in _WEB_API_ASSET_TYPES:
        return []

    contracts = [
        build_scan_profile_contract(
            scan_type=scan_type,
            asset_type=asset_type,
            target=target,
            config=prepare_scan_config(
                scan_type=scan_type,
                asset_type=asset_type,
                asset_target=target,
                config={"profile": scan_type},
            ),
        )
        for scan_type in ("recon", "vuln", "full")
    ]
    contracts.append(
        build_scan_profile_contract(
            scan_type="full",
            asset_type=asset_type,
            target=target,
            config=prepare_scan_config(
                scan_type="full",
                asset_type=asset_type,
                asset_target=target,
                config={
                    "profile_id": FIELD_VALIDATION_EXTERNAL_WEB_API_PROFILE_ID,
                    "profile": {
                        "id": FIELD_VALIDATION_EXTERNAL_WEB_API_PROFILE_ID,
                        "variant": "field_validation",
                    },
                },
            ),
        )
    )
    return [contract for contract in contracts if isinstance(contract, dict)]


def build_scan_profile_contract(
    *,
    scan_type: str,
    asset_type: str,
    target: str,
    config: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Describe exactly what a product-safe profile will run for a target."""
    if asset_type not in _WEB_API_ASSET_TYPES or scan_type not in _PROFILE_CATALOG:
        return None

    normalized_config = deepcopy(config or {})
    execution = (
        normalized_config.get("execution", {})
        if isinstance(normalized_config.get("execution"), dict)
        else {}
    )
    verification_policy = (
        normalized_config.get("verification_policy", {})
        if isinstance(normalized_config.get("verification_policy"), dict)
        else {}
    )
    scope = (
        normalized_config.get("scope", {})
        if isinstance(normalized_config.get("scope"), dict)
        else {}
    )
    targeting = (
        normalized_config.get("targeting", {})
        if isinstance(normalized_config.get("targeting"), dict)
        else {}
    )
    profile_id = str(
        normalized_config.get("profile_id")
        or (
            normalized_config.get("profile", {}).get("id")
            if isinstance(normalized_config.get("profile"), dict)
            else ""
        )
        or DEFAULT_EXTERNAL_WEB_API_PROFILE_ID
    )
    variant_meta = _profile_variant_for(profile_id=profile_id, scan_type=scan_type)
    catalog = variant_meta["catalog"]
    scheduled_tools = [
        entry["tool"] for entry in _external_web_api_toolchain(scan_type, config=normalized_config)
    ]
    allowed_live_tools = _normalize_string_list(execution.get("allowed_live_tools")) or sorted(
        _SAFE_LIVE_TOOLS
    )
    conditional_live_tools = [
        tool
        for tool in _normalize_string_list(verification_policy.get("allowed_tools"))
        if tool in _SAFE_LIVE_TOOLS and tool not in scheduled_tools
    ]
    approval_required_tools = [
        tool
        for tool in _normalize_string_list(execution.get("approval_required_tools"))
        if tool in scheduled_tools and tool not in allowed_live_tools
    ]
    derived_tools = [tool for tool in scheduled_tools if tool in _DERIVED_TOOLS]
    live_tools = [
        tool
        for tool in scheduled_tools
        if tool in allowed_live_tools and tool not in _DERIVED_TOOLS
    ]
    unsupported_tools = [tool for tool in _PRODUCT_UNSUPPORTED_TOOLS if tool not in live_tools]
    allowed_hosts = _normalize_string_list(scope.get("allowed_hosts"))
    allowed_domains = _normalize_string_list(scope.get("allowed_domains"))
    execution_mode = str(execution.get("mode") or "controlled_live_local")
    target_policy = str(execution.get("target_policy") or "local_only")

    scope_summary = (
        "Loopback/private targets only."
        if target_policy == "local_only"
        else _format_scope_summary(
            allowed_hosts=allowed_hosts,
            allowed_domains=allowed_domains,
            fallback_target=str(targeting.get("host") or target),
        )
    )

    return {
        "contract_id": f"{profile_id}:{scan_type}",
        "scan_type": scan_type,
        "profile_id": profile_id,
        "profile_variant": variant_meta["variant"],
        "name": catalog["name"],
        "description": catalog["description"],
        "duration": catalog["duration"],
        "priority": catalog["priority"],
        "execution_mode": execution_mode,
        "target_policy": target_policy,
        "scope_summary": scope_summary,
        "target_profile_keys": _contract_target_profile_keys(profile_id=profile_id, scan_type=scan_type),
        "requires_preflight": bool(variant_meta["requires_preflight"]),
        "benchmark_inputs_enabled": bool(normalized_config.get("benchmark_inputs_enabled", False)),
        "scheduled_tools": scheduled_tools,
        "live_tools": live_tools,
        "approval_required_tools": approval_required_tools,
        "conditional_live_tools": conditional_live_tools,
        "derived_tools": derived_tools,
        "unsupported_tools": unsupported_tools,
        "guardrails": [
            "No silent simulation in product-safe live modes.",
            "Only declared scope hosts/domains may be reached.",
            "Safe verification is limited to selected finding classes.",
            "Demo simulation mode is reserved for local validation only.",
        ],
        "honesty_notes": [
            "Unsupported target-execution tools are excluded from this live profile instead of being simulated.",
            "AI triage and report generation are derived from persisted artifacts, not direct target execution.",
            "Conditional verification tools run only when findings and policy allow them.",
        ],
        "sellable": True,
    }


def preflight_scan_profile_contract(
    *,
    asset_type: str,
    target: str,
    contract_id: str,
    scan_mode: str = "autonomous",
    methodology: str | None = None,
    authorization_acknowledged: bool = False,
    approved_live_tools: list[str] | None = None,
    credentials: dict[str, Any] | None = None,
    repository: dict[str, Any] | None = None,
    scope: dict[str, Any] | None = None,
    ai_provider_readiness: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a frontend-visible preflight payload before scan launch."""
    profile_id, _, scan_type = str(contract_id).partition(":")
    if not profile_id or not scan_type:
        raise ValueError(f"Unknown scan profile contract: {contract_id}")

    prepared = prepare_scan_config(
        scan_type=scan_type,
        asset_type=asset_type,
        asset_target=target,
        config={
            "profile_id": profile_id,
            "profile": {
                "id": profile_id,
            },
        },
    )
    requested_tools = _normalize_string_list(approved_live_tools)
    execution = prepared.get("execution", {})
    if isinstance(execution, dict):
        auto_live_tools = _normalize_string_list(execution.get("allowed_live_tools"))
        approval_required = _normalize_string_list(execution.get("approval_required_tools"))
        approved_tools = [tool for tool in requested_tools if tool in approval_required]
        execution["allowed_live_tools"] = list(dict.fromkeys(auto_live_tools + approved_tools))
        prepared["execution"] = execution

    contract = build_scan_profile_contract(
        scan_type=scan_type,
        asset_type=asset_type,
        target=target,
        config=prepared,
    )
    target_context = derive_target_context(asset_type=asset_type, target=target)
    target_profile_hypotheses = _preflight_target_profile_hypotheses(
        asset_type=asset_type,
        target=target,
        contract=contract,
    )
    auth_material = _build_preflight_auth_material(
        credentials=credentials or {},
        target_profile_hypotheses=target_profile_hypotheses,
    )
    repository_context = _build_repository_context(
        methodology=methodology,
        repository=repository or {},
    )
    rate_limits = dict(prepared.get("rate_limits") or {})
    verification_policy = dict(prepared.get("verification_policy") or {})
    stateful_testing = dict(prepared.get("stateful_testing") or {})
    ai_readiness = dict(ai_provider_readiness or {})

    is_external_target = not _is_local_asset_host(target_context["host"])
    authorization_required = is_external_target
    scope_authorization = {
        "required": authorization_required,
        "acknowledged": bool(authorization_acknowledged),
        "status": (
            "not_required"
            if not authorization_required
            else
            "acknowledged"
            if authorization_acknowledged
            else "missing_acknowledgement"
        ),
        "message": (
            "Authorization acknowledgement is not required for loopback/private targets."
            if not authorization_required
            else
            "Authorization acknowledgement recorded."
            if authorization_acknowledged
            else "Authorized-scope acknowledgement is required before external launch."
        ),
    }

    warnings: list[str] = []
    blocking_issues: list[str] = []

    if scope_authorization["required"] and not scope_authorization["acknowledged"]:
        blocking_issues.append("Authorization acknowledgement is required for external targets.")

    ai_state = str(ai_readiness.get("operator_state") or "configured_but_fallback")
    if ai_state in {"disabled_by_config", "missing_api_key", "provider_unreachable"}:
        blocking_issues.append(
            "AI/provider readiness is not healthy enough for frontend launch. Check Runtime & Providers."
        )

    if str(contract.get("profile_variant")) == "field_validation":
        if bool(contract.get("benchmark_inputs_enabled")):
            blocking_issues.append("Field validation must keep benchmark-only inputs disabled.")
        if not prepared.get("verification_policy"):
            blocking_issues.append("Field validation requires a live verification policy.")

    if methodology == "white_box" and not repository_context["repository_present"]:
        blocking_issues.append("White-box methodology requires repository context before launch.")

    if auth_material["status"] == "recommended_but_missing":
        warnings.append("Auth material is missing for a target shape that likely benefits from authenticated replay.")
    if scan_mode == "manual" and not scope:
        warnings.append("Manual mode is running without custom scope overrides.")

    settings = get_settings()
    http_rate = int(rate_limits.get("http_requests_per_minute", 0) or 0)
    if is_external_target and http_rate > int(settings.external_scan_rate_limit):
        blocking_issues.append(
            f"HTTP request rate {http_rate}/min exceeds the external-target limit of {settings.external_scan_rate_limit}/min."
        )

    return {
        "contract": contract,
        "target_context": {
            **target_context,
            "is_local_target": _is_local_asset_host(target_context["host"]),
            "is_external_target": is_external_target,
            "selected_asset_type": asset_type,
        },
        "target_profile_hypotheses": [item.model_dump(mode="json") for item in target_profile_hypotheses],
        "execution_contract": {
            "scheduled_tools": list(contract.get("scheduled_tools") or []),
            "live_tools": list(contract.get("live_tools") or []),
            "approval_required_tools": list(contract.get("approval_required_tools") or []),
            "conditional_live_tools": list(contract.get("conditional_live_tools") or []),
            "derived_tools": list(contract.get("derived_tools") or []),
            "unsupported_tools": list(contract.get("unsupported_tools") or []),
        },
        "scope_authorization": scope_authorization,
        "auth_material": auth_material,
        "repository_context": repository_context,
        "rate_limit_policy": {
            "http_requests_per_minute": http_rate,
            "ffuf_requests_per_minute": int(rate_limits.get("ffuf_requests_per_minute", 0) or 0),
            "nuclei_requests_per_minute": int(rate_limits.get("nuclei_requests_per_minute", 0) or 0),
            "sqlmap_threads": int(rate_limits.get("sqlmap_threads", 0) or 0),
            "external_scan_rate_limit": int(settings.external_scan_rate_limit),
            "scope": dict(scope or {}),
        },
        "safe_replay_policy": {
            "verification_mode": str(verification_policy.get("mode") or ""),
            "target_policy": str(verification_policy.get("target_policy") or ""),
            "max_verifications_per_type": int(
                verification_policy.get("max_verifications_per_type", 0) or 0
            ),
            "max_dynamic_nodes_per_scan": int(
                verification_policy.get("max_dynamic_nodes_per_scan", 0) or 0
            ),
            "allowed_vulnerability_types": _normalize_string_list(
                verification_policy.get("allowed_vulnerability_types")
            ),
            "stateful_testing_enabled": bool(stateful_testing.get("enabled")),
            "stateful_max_pages": int(stateful_testing.get("max_pages", 0) or 0),
            "stateful_max_replays": int(stateful_testing.get("max_replays", 0) or 0),
        },
        "ai_provider_readiness": ai_readiness,
        "benchmark_inputs_enabled": bool(contract.get("benchmark_inputs_enabled")),
        "approved_live_tools": [
            tool
            for tool in _normalize_string_list(execution.get("allowed_live_tools"))
            if tool in _normalize_string_list(contract.get("live_tools"))
            and tool not in _FIELD_VALIDATION_AUTO_LIVE_TOOLS
        ],
        "warnings": warnings,
        "blocking_issues": blocking_issues,
        "can_launch": not blocking_issues,
    }


def _external_web_api_toolchain(
    scan_type: str,
    config: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """Truthful product-safe toolchain for the External Web + API profile."""
    recon_tools = [
        {"phase": "scope_validation", "tool": "scope_check"},
        {"phase": "recon", "tool": "subfinder"},
        {"phase": "recon", "tool": "amass"},
        {"phase": "recon", "tool": "nmap_discovery"},
        {"phase": "recon", "tool": "httpx_probe"},
    ]
    if scan_type == "recon":
        return recon_tools
    vuln_scan_tools = [
        {"phase": "vuln_scan", "tool": "nuclei"},
        {"phase": "vuln_scan", "tool": "zap"},
        {"phase": "vuln_scan", "tool": "nikto"},
        {"phase": "vuln_scan", "tool": "sqlmap"},
        {"phase": "vuln_scan", "tool": "dalfox"},
    ]
    if _profile_declares_graphql_surface(config):
        vuln_scan_tools.append({"phase": "vuln_scan", "tool": "graphql_cop"})
    vuln_scan_tools.append({"phase": "vuln_scan", "tool": "cors_scanner"})
    vuln_scan_tools.append({"phase": "vuln_scan", "tool": "jwt_tool"})
    if scan_type == "vuln":
        return [
            *recon_tools,
            {"phase": "enum", "tool": "web_interact"},
            {"phase": "enum", "tool": "nmap_svc"},
            {"phase": "enum", "tool": "ffuf"},
            *vuln_scan_tools,
            {"phase": "ai_analysis", "tool": "ai_triage"},
            {"phase": "report_gen", "tool": "report_gen"},
        ]
    profile_id = ""
    if isinstance(config, dict):
        profile_id = str(
            config.get("profile_id")
            or (
                config.get("profile", {}).get("id")
                if isinstance(config.get("profile"), dict)
                else ""
            )
        )
    if profile_id == FIELD_VALIDATION_EXTERNAL_WEB_API_PROFILE_ID:
        toolchain = [
            *recon_tools,
            {"phase": "enum", "tool": "web_interact"},
            {"phase": "enum", "tool": "nmap_svc"},
            {"phase": "enum", "tool": "ffuf"},
            {"phase": "vuln_scan", "tool": "nuclei"},
            {"phase": "vuln_scan", "tool": "zap"},
        ]
        if _profile_declares_graphql_surface(config):
            toolchain.append({"phase": "vuln_scan", "tool": "graphql_cop"})
        toolchain.extend(
            [
                {"phase": "vuln_scan", "tool": "cors_scanner"},
                {"phase": "vuln_scan", "tool": "sqlmap"},
                {"phase": "vuln_scan", "tool": "dalfox"},
                {"phase": "vuln_scan", "tool": "nikto"},
                {"phase": "vuln_scan", "tool": "jwt_tool"},
                {"phase": "ai_analysis", "tool": "ai_triage"},
                {"phase": "report_gen", "tool": "report_gen"},
            ]
        )
        return toolchain
    if scan_type == "full":
        return [
            *recon_tools,
            {"phase": "enum", "tool": "web_interact"},
            {"phase": "enum", "tool": "nmap_svc"},
            {"phase": "enum", "tool": "ffuf"},
            *vuln_scan_tools,
            {"phase": "ai_analysis", "tool": "ai_triage"},
            {"phase": "report_gen", "tool": "report_gen"},
        ]
    return []


def _profile_declares_graphql_surface(config: dict[str, Any] | None) -> bool:
    if not isinstance(config, dict):
        return True

    selected_checks = config.get("selected_checks", {})
    if not isinstance(selected_checks, dict):
        return True

    for collection_key in ("http_probe_paths", "content_paths", "api_checks"):
        values = selected_checks.get(collection_key, [])
        if not isinstance(values, list):
            continue
        for value in values:
            if "graphql" in str(value or "").strip().lower():
                return True
    return False


def _profile_base_for_id(
    *,
    profile_id: str,
    asset_type: str,
    target: str,
    scan_type: str,
) -> dict[str, Any] | None:
    if profile_id == DEFAULT_EXTERNAL_WEB_API_PROFILE_ID:
        return external_web_api_profile(
            asset_type=asset_type,
            target=target,
            scan_type=scan_type,
        )
    if profile_id == FIELD_VALIDATION_EXTERNAL_WEB_API_PROFILE_ID:
        return external_web_api_field_validation_profile(
            asset_type=asset_type,
            target=target,
            scan_type=scan_type,
        )
    return None


def _profile_variant_for(*, profile_id: str, scan_type: str) -> dict[str, Any]:
    variant = _PROFILE_VARIANTS.get(profile_id) or _PROFILE_VARIANTS[DEFAULT_EXTERNAL_WEB_API_PROFILE_ID]
    catalog = deepcopy(_PROFILE_CATALOG.get(scan_type, {}))
    catalog.update(deepcopy((variant.get("catalog") or {}).get(scan_type, {})))
    return {
        "variant": str(variant.get("variant") or "standard"),
        "requires_preflight": bool(variant.get("requires_preflight")),
        "catalog": catalog,
    }


def _contract_target_profile_keys(*, profile_id: str, scan_type: str) -> list[str]:
    if profile_id == FIELD_VALIDATION_EXTERNAL_WEB_API_PROFILE_ID:
        return [
            "spa_rest_api",
            "graphql_heavy_application",
            "auth_heavy_admin_portal",
            "workflow_heavy_commerce",
        ]
    if scan_type == "recon":
        return ["spa_rest_api", "traditional_server_rendered"]
    if scan_type == "vuln":
        return ["spa_rest_api", "traditional_server_rendered", "graphql_heavy_application"]
    return [
        "spa_rest_api",
        "traditional_server_rendered",
        "graphql_heavy_application",
        "auth_heavy_admin_portal",
        "workflow_heavy_commerce",
        "upload_parser_heavy",
    ]


def _load_target_profile_catalog() -> TargetProfileCatalog:
    payload = yaml.safe_load(_TARGET_PROFILE_PATH.read_text()) or {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"Target profile file must contain a YAML object: {_TARGET_PROFILE_PATH}")
    return TargetProfileCatalog.model_validate(payload)


def _preflight_target_profile_hypotheses(
    *,
    asset_type: str,
    target: str,
    contract: dict[str, Any],
) -> list[TargetProfileHypothesis]:
    catalog = _load_target_profile_catalog()
    route_text = " ".join(
        part
        for part in (
            target,
            str(contract.get("profile_id") or ""),
            str(contract.get("name") or ""),
        )
        if str(part).strip()
    ).lower()
    contract_target_profiles = {
        str(item).strip()
        for item in _normalize_string_list(contract.get("target_profile_keys"))
    }

    hypotheses: list[TargetProfileHypothesis] = []
    for profile in catalog.target_profiles:
        score = 0.0
        evidence: list[str] = []
        if profile.key in contract_target_profiles:
            score += 0.36
            evidence.append("selected execution contract targets this profile")

        route_matches = [
            indicator
            for indicator in profile.route_indicators
            if indicator.strip().lower() in route_text
        ]
        if route_matches:
            score += min(0.16 * len(route_matches), 0.32)
            evidence.append(f"route indicators: {', '.join(route_matches[:3])}")

        if asset_type == "api" and profile.key in {"spa_rest_api", "graphql_heavy_application"}:
            score += 0.12
            evidence.append("API asset type matches profile")
        if asset_type == "web_app" and profile.key in {
            "spa_rest_api",
            "traditional_server_rendered",
            "auth_heavy_admin_portal",
            "workflow_heavy_commerce",
            "upload_parser_heavy",
        }:
            score += 0.08
            evidence.append("web-app asset type matches profile")

        if score < 0.20:
            continue
        hypotheses.append(
            TargetProfileHypothesis(
                key=profile.key,
                confidence=round(min(score, 0.92), 3),
                evidence=evidence,
                preferred_capability_pack_keys=list(profile.preferred_capability_pack_keys),
                planner_bias_rules=list(profile.planner_bias_rules),
                benchmark_target_keys=list(profile.benchmark_target_keys),
            )
        )

    if not hypotheses and contract_target_profiles:
        for key in sorted(contract_target_profiles):
            profile = next((item for item in catalog.target_profiles if item.key == key), None)
            if profile is None:
                continue
            hypotheses.append(
                TargetProfileHypothesis(
                    key=profile.key,
                    confidence=0.45,
                    evidence=["fallback to contract-supported target profile"],
                    preferred_capability_pack_keys=list(profile.preferred_capability_pack_keys),
                    planner_bias_rules=list(profile.planner_bias_rules),
                    benchmark_target_keys=list(profile.benchmark_target_keys),
                )
            )
            break

    hypotheses.sort(key=lambda item: (-item.confidence, item.key))
    return hypotheses[:3]


def _build_preflight_auth_material(
    *,
    credentials: dict[str, Any],
    target_profile_hypotheses: list[TargetProfileHypothesis],
) -> dict[str, Any]:
    auth_type = str(
        credentials.get("authType")
        or credentials.get("auth_type")
        or "none"
    ).strip() or "none"
    username_present = bool(str(credentials.get("username") or "").strip())
    password_present = bool(str(credentials.get("password") or "").strip())
    cookie_present = bool(str(credentials.get("cookie") or "").strip())
    bearer_token_present = bool(str(credentials.get("bearerToken") or credentials.get("bearer_token") or "").strip())
    client_id_present = bool(str(credentials.get("clientId") or credentials.get("client_id") or "").strip())
    client_secret_present = bool(
        str(credentials.get("clientSecret") or credentials.get("client_secret") or "").strip()
    )
    token_url_present = bool(str(credentials.get("tokenUrl") or credentials.get("token_url") or "").strip())
    material_present = any(
        (
            username_present,
            password_present,
            cookie_present,
            bearer_token_present,
            client_id_present and client_secret_present,
        )
    )
    recommended = any(
        hypothesis.key in {"auth_heavy_admin_portal", "workflow_heavy_commerce"}
        for hypothesis in target_profile_hypotheses
    )

    status = "provided" if material_present else "not_required"
    if auth_type != "none" and not material_present:
        status = "declared_but_missing"
    elif recommended and not material_present:
        status = "recommended_but_missing"

    return {
        "auth_type": auth_type,
        "status": status,
        "material_present": material_present,
        "recommended": recommended,
        "username_present": username_present,
        "password_present": password_present,
        "cookie_present": cookie_present,
        "bearer_token_present": bearer_token_present,
        "oauth_client_present": client_id_present and client_secret_present and token_url_present,
    }


def _build_repository_context(
    *,
    methodology: str | None,
    repository: dict[str, Any],
) -> dict[str, Any]:
    url = str(repository.get("url") or "").strip()
    branch = str(repository.get("branch") or "").strip()
    token_present = bool(str(repository.get("token") or "").strip())
    repository_present = bool(url)
    required = methodology == "white_box"
    return {
        "required": required,
        "repository_present": repository_present,
        "url": url or None,
        "branch": branch or None,
        "token_present": token_present,
        "status": (
            "provided"
            if repository_present
            else "required_but_missing"
            if required
            else "optional"
        ),
    }


def _format_scope_summary(
    *,
    allowed_hosts: list[str],
    allowed_domains: list[str],
    fallback_target: str,
) -> str:
    if allowed_hosts and allowed_domains:
        return (
            f"Hosts: {', '.join(allowed_hosts)}. Domains: {', '.join(allowed_domains)}."
        )
    if allowed_hosts:
        return f"Hosts: {', '.join(allowed_hosts)}."
    if allowed_domains:
        return f"Domains: {', '.join(allowed_domains)}."
    return f"Target scope anchored to {fallback_target}."


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
    path_prefix = (parsed.path or "").rstrip("/")
    base_url = f"{scheme}://{netloc}{path_prefix}".rstrip("/")

    return {
        "scheme": scheme,
        "host": host,
        "base_url": base_url,
        "path_prefix": path_prefix,
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
