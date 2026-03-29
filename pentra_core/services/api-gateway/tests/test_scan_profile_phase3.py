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
    assert config["execution"]["mode"] == "controlled_live_external"
    assert config["execution"]["target_policy"] == "external_authorized"
    assert config["execution_contract"]["approval_required_tools"] == []
    assert "subfinder" in config["execution_contract"]["live_tools"]
    assert "amass" in config["execution_contract"]["live_tools"]
    assert "nmap_discovery" in config["execution_contract"]["live_tools"]
    assert "nmap_svc" in config["execution_contract"]["live_tools"]
    assert "zap" in config["execution_contract"]["live_tools"]
    assert config["execution_contract"]["unsupported_tools"] == []


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


def test_prepare_scan_config_local_profile_does_not_inject_repo_demo_stateful_defaults():
    from pentra_common.profiles import prepare_scan_config

    config = prepare_scan_config(
        scan_type="full",
        asset_type="web_app",
        asset_target="http://127.0.0.1:3001",
        config=None,
    )

    assert config["selected_checks"]["sqlmap"]["path"] == "/"
    assert config["selected_checks"]["authenticated_crawling"] is False
    assert config["selected_checks"]["workflow_replay"] is False
    assert config["selected_checks"]["stateful_testing"] is False
    assert config["stateful_testing"]["enabled"] is False
    assert config["stateful_testing"]["seed_paths"] == ["/"]
    assert config["stateful_testing"]["auth"]["success_path_contains"] == ""


def test_prepare_scan_config_preserves_target_path_prefix_for_subpath_apps():
    from pentra_common.profiles import prepare_scan_config

    config = prepare_scan_config(
        scan_type="full",
        asset_type="web_app",
        asset_target="http://127.0.0.1:3003/WebGoat",
        config=None,
    )

    assert config["targeting"]["base_url"] == "http://127.0.0.1:3003/WebGoat"
    assert config["command_context"]["base_url"] == "http://127.0.0.1:3003/WebGoat"


def test_list_scan_profile_contracts_returns_truthful_catalog():
    from pentra_common.profiles import list_scan_profile_contracts

    profiles = list_scan_profile_contracts(
        asset_type="web_app",
        target="https://app.example.com",
    )

    assert [profile["contract_id"] for profile in profiles] == [
        "external_web_api_v1:recon",
        "external_web_api_v1:vuln",
        "external_web_api_v1:full",
        "external_web_api_field_validation_v1:full",
    ]
    assert profiles[0]["approval_required_tools"] == []
    assert profiles[0]["live_tools"] == [
        "scope_check",
        "subfinder",
        "amass",
        "nmap_discovery",
        "httpx_probe",
    ]
    assert profiles[1]["conditional_live_tools"] == ["sqlmap_verify", "custom_poc"]
    assert profiles[1]["derived_tools"] == ["ai_triage", "report_gen"]
    assert profiles[2]["derived_tools"] == ["ai_triage", "report_gen"]
    assert profiles[3]["profile_variant"] == "field_validation"
    assert profiles[3]["requires_preflight"] is True
    assert profiles[3]["benchmark_inputs_enabled"] is False


def test_preflight_scan_profile_contract_blocks_external_launch_without_acknowledgement() -> None:
    from pentra_common.profiles import preflight_scan_profile_contract

    preflight = preflight_scan_profile_contract(
        asset_type="web_app",
        target="https://portal.example.com",
        contract_id="external_web_api_field_validation_v1:full",
        scan_mode="manual",
        methodology="grey_box",
        authorization_acknowledged=False,
        credentials={},
        repository={},
        scope={"in_scope": ["/"], "out_scope": [], "rate_limit": 30},
        ai_provider_readiness={"operator_state": "configured_and_healthy"},
    )

    assert preflight["contract"]["profile_variant"] == "field_validation"
    assert preflight["scope_authorization"]["required"] is True
    assert preflight["scope_authorization"]["status"] == "missing_acknowledgement"
    assert preflight["benchmark_inputs_enabled"] is False
    assert preflight["can_launch"] is False
    assert preflight["blocking_issues"]


def test_preflight_scan_profile_contract_allows_field_validation_with_runtime_ready_inputs() -> None:
    from pentra_common.profiles import preflight_scan_profile_contract

    preflight = preflight_scan_profile_contract(
        asset_type="api",
        target="https://api.example.com/graphql",
        contract_id="external_web_api_field_validation_v1:full",
        scan_mode="manual",
        methodology="grey_box",
        authorization_acknowledged=True,
        approved_live_tools=["ffuf", "zap"],
        credentials={"type": "bearer", "bearer_token": "token"},
        repository={"url": "https://github.com/example/private", "branch": "main"},
        scope={"in_scope": ["/graphql"], "out_scope": [], "rate_limit": 20},
        ai_provider_readiness={"operator_state": "configured_and_healthy"},
    )

    assert preflight["can_launch"] is True
    assert preflight["scope_authorization"]["status"] == "acknowledged"
    assert preflight["target_profile_hypotheses"]
    assert preflight["execution_contract"]["live_tools"]
    assert "ffuf" in preflight["execution_contract"]["live_tools"]
    assert preflight["approved_live_tools"] == []
    assert "ffuf" not in preflight["execution_contract"]["approval_required_tools"]
    assert preflight["safe_replay_policy"]["verification_mode"]


def test_preflight_scan_profile_contract_marks_local_field_validation_as_not_required() -> None:
    from pentra_common.profiles import preflight_scan_profile_contract

    preflight = preflight_scan_profile_contract(
        asset_type="api",
        target="http://127.0.0.1:8088",
        contract_id="external_web_api_field_validation_v1:full",
        scan_mode="autonomous",
        authorization_acknowledged=False,
        credentials={},
        repository={},
        scope={"in_scope": ["/graphql"], "out_scope": [], "rate_limit": 20},
        ai_provider_readiness={"operator_state": "configured_and_healthy"},
    )

    assert preflight["scope_authorization"]["required"] is False
    assert preflight["scope_authorization"]["status"] == "not_required"
    assert "loopback/private" in preflight["scope_authorization"]["message"]
    assert preflight["can_launch"] is True
