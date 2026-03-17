from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_prepare_scan_config_defaults_external_web_api_profile():
    from pentra_common.profiles import prepare_scan_config

    config = prepare_scan_config(
        scan_type="full",
        asset_type="web_app",
        asset_target="https://app.example.com",
        config=None,
    )

    assert config["profile_id"] == "external_web_api_v1"
    assert config["targeting"]["host"] == "app.example.com"
    assert config["targeting"]["base_url"] == "https://app.example.com"
    assert config["scope"]["allowed_hosts"] == ["app.example.com"]
    assert config["command_context"]["http_rate_limit"] == 120
    assert config["execution"]["mode"] == "controlled_live_scoped"
    assert config["execution"]["target_policy"] == "in_scope"
    assert config["execution_contract"]["live_tools"] == [
        "scope_check",
        "httpx_probe",
        "web_interact",
        "ffuf",
        "nuclei",
        "sqlmap",
    ]
    assert "subfinder" in config["execution_contract"]["unsupported_tools"]
    assert "zap" in config["execution_contract"]["unsupported_tools"]


def test_prepare_scan_config_preserves_explicit_overrides():
    from pentra_common.profiles import prepare_scan_config

    config = prepare_scan_config(
        scan_type="vuln",
        asset_type="api",
        asset_target="https://api.example.com",
        config={
            "rate_limits": {"http_requests_per_minute": 55},
            "scope": {"max_endpoints": 25},
        },
    )

    assert config["profile_id"] == "external_web_api_v1"
    assert config["rate_limits"]["http_requests_per_minute"] == 55
    assert config["scope"]["max_endpoints"] == 25


def test_prepare_scan_config_uses_local_live_mode_for_loopback_targets():
    from pentra_common.profiles import prepare_scan_config

    config = prepare_scan_config(
        scan_type="vuln",
        asset_type="api",
        asset_target="http://127.0.0.1:8088",
        config=None,
    )

    assert config["execution"]["mode"] == "controlled_live_local"
    assert config["execution"]["target_policy"] == "local_only"


def test_list_scan_profile_contracts_returns_truthful_catalog():
    from pentra_common.profiles import list_scan_profile_contracts

    profiles = list_scan_profile_contracts(
        asset_type="web_app",
        target="https://app.example.com",
    )

    assert [profile["scan_type"] for profile in profiles] == ["recon", "vuln", "full"]
    assert profiles[0]["live_tools"] == ["scope_check", "httpx_probe"]
    assert profiles[1]["conditional_live_tools"] == ["sqlmap_verify", "custom_poc"]
    assert profiles[2]["derived_tools"] == ["ai_triage", "report_gen"]
