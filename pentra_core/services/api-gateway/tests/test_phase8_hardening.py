from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_redact_secrets_masks_nested_values():
    from app.security.redaction import redact_secrets

    payload = {
        "headers": {"Authorization": "Bearer secret-token"},
        "credentials": {"password": "sup3r-secret", "username": "demo"},
        "nested": [{"session_cookie": "abc123"}],
    }

    redacted = redact_secrets(payload)

    assert redacted["headers"]["Authorization"] == "[REDACTED]"
    assert redacted["credentials"] == "[REDACTED]"
    assert redacted["nested"][0]["session_cookie"] == "[REDACTED]"


def test_enforce_safe_scan_config_rejects_out_of_scope_allowed_host():
    from pentra_common.profiles import enforce_safe_scan_config, prepare_scan_config

    config = prepare_scan_config(
        scan_type="full",
        asset_type="web_app",
        asset_target="https://app.example.com",
        config={"scope": {"allowed_hosts": ["admin.other-example.com"]}},
    )

    try:
        enforce_safe_scan_config(
            scan_type="full",
            asset_type="web_app",
            asset_target="https://app.example.com",
            config=config,
        )
    except ValueError as exc:
        assert "out-of-scope host" in str(exc)
    else:  # pragma: no cover - explicit failure branch
        raise AssertionError("Expected out-of-scope host validation to fail")


def test_enforce_safe_scan_config_rejects_excessive_http_rate_limit():
    from pentra_common.profiles import enforce_safe_scan_config, prepare_scan_config

    config = prepare_scan_config(
        scan_type="full",
        asset_type="web_app",
        asset_target="http://127.0.0.1:8088",
        config={"rate_limits": {"http_requests_per_minute": 9999}},
    )

    try:
        enforce_safe_scan_config(
            scan_type="full",
            asset_type="web_app",
            asset_target="http://127.0.0.1:8088",
            config=config,
        )
    except ValueError as exc:
        assert "http_requests_per_minute" in str(exc)
    else:  # pragma: no cover - explicit failure branch
        raise AssertionError("Expected excessive rate limit validation to fail")


def test_enforce_safe_scan_config_rejects_demo_mode_by_default():
    from pentra_common.profiles import enforce_safe_scan_config, prepare_scan_config

    config = prepare_scan_config(
        scan_type="full",
        asset_type="web_app",
        asset_target="https://app.example.com",
        config={"execution": {"mode": "demo_simulated"}},
    )

    try:
        enforce_safe_scan_config(
            scan_type="full",
            asset_type="web_app",
            asset_target="https://app.example.com",
            config=config,
        )
    except ValueError as exc:
        assert "demo_simulated" in str(exc)
    else:  # pragma: no cover - explicit failure branch
        raise AssertionError("Expected demo mode validation to fail")


def test_with_request_metadata_includes_idempotency_key():
    from app.services.scan_service import _with_request_metadata

    payload = _with_request_metadata(
        {"profile_id": "external_web_api_v1"},
        idempotency_key="scan-submit-123",
    )

    assert payload["profile_id"] == "external_web_api_v1"
    assert payload["request_metadata"]["idempotency_key"] == "scan-submit-123"
    assert "submitted_at" in payload["request_metadata"]


def test_apply_artifact_retention_metadata_sets_expiry():
    from pentra_common.storage.retention import apply_artifact_retention_metadata

    payload = apply_artifact_retention_metadata({"tool": "nuclei"}, policy="advisory")

    assert payload["tool"] == "nuclei"
    assert payload["retention_policy"] == "advisory"
    assert payload["retention_days"] >= 1
    assert "expires_at" in payload


def test_build_dev_bypass_user_uses_env_settings(monkeypatch):
    from pentra_common.config.settings import get_settings
    from app.security.runtime_auth import build_dev_bypass_user

    monkeypatch.setenv("DEV_AUTH_USER_ID", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    monkeypatch.setenv("DEV_AUTH_TENANT_ID", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    monkeypatch.setenv("DEV_AUTH_EMAIL", "phase8@pentra.local")
    monkeypatch.setenv("DEV_AUTH_ROLES", "owner,admin")
    monkeypatch.setenv("DEV_AUTH_TIER", "enterprise")
    get_settings.cache_clear()

    try:
        user = build_dev_bypass_user()
    finally:
        get_settings.cache_clear()

    assert str(user.user_id) == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert str(user.tenant_id) == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    assert user.email == "phase8@pentra.local"
    assert user.roles == ["owner", "admin"]
    assert user.tier == "enterprise"
