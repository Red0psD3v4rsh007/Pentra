from __future__ import annotations

from pentra_core.scripts.local.run_phase8_capability_matrix import (
    evaluate_capability_assessment,
    resolve_scan_plan_config,
)


def test_evaluate_capability_assessment_reports_recall_thresholds() -> None:
    findings = [
        {"vulnerability_type": "auth_bypass", "verification_state": "verified"},
        {"vulnerability_type": "idor", "verification_state": "verified"},
        {"vulnerability_type": "sql_injection", "verification_state": "detected"},
        {"vulnerability_type": "workflow_bypass", "verification_state": "verified"},
    ]

    assessment = evaluate_capability_assessment(
        findings=findings,
        expectations={
            "expected_vulnerability_types": [
                "auth_bypass",
                "idor",
                "sql_injection",
                "workflow_bypass",
            ],
            "expected_verified_types": [
                "auth_bypass",
                "idor",
                "workflow_bypass",
            ],
            "minimum_detected_recall": 1.0,
            "minimum_verified_recall": 1.0,
            "minimum_verified_share": 0.5,
        },
    )

    assert assessment["detected_recall"] == 1.0
    assert assessment["verified_recall"] == 1.0
    assert assessment["verified_share"] == 0.75
    assert assessment["missed_expected_types"] == []
    assert assessment["unexpected_detected_types"] == []
    assert assessment["meets_target_bar"] is True


def test_evaluate_capability_assessment_flags_missed_and_unexpected_types() -> None:
    findings = [
        {"vulnerability_type": "auth_bypass", "verification_state": "verified"},
        {"vulnerability_type": "xss", "verification_state": "detected"},
    ]

    assessment = evaluate_capability_assessment(
        findings=findings,
        expectations={
            "expected_vulnerability_types": ["auth_bypass", "idor"],
            "expected_verified_types": ["auth_bypass", "idor"],
            "minimum_detected_recall": 1.0,
            "minimum_verified_recall": 1.0,
            "minimum_verified_share": 0.5,
        },
    )

    assert assessment["detected_recall"] == 0.5
    assert assessment["verified_recall"] == 0.5
    assert assessment["missed_expected_types"] == ["idor"]
    assert assessment["unexpected_detected_types"] == ["xss"]
    assert assessment["meets_target_bar"] is False


def test_resolve_scan_plan_config_supports_templates_and_overrides() -> None:
    config = resolve_scan_plan_config(
        config_template="stateful_full",
        config_overrides={
            "profile_id": "external_web_api_v1",
            "stateful_testing": {"crawl_max_depth": 4},
        },
    )

    assert config["profile_id"] == "external_web_api_v1"
    assert config["stateful_testing"]["crawl_max_depth"] == 4
    assert config["stateful_testing"]["enabled"] is True
