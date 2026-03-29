from __future__ import annotations

from pathlib import Path

from pentra_core.scripts.local.run_phase9_capability_matrix import (
    derive_phase9_target_status,
    load_phase9_manifest,
    summarize_phase9_targets,
)


def test_load_phase9_manifest_expands_target_manifests() -> None:
    manifest = load_phase9_manifest(
        Path("pentra_core/dev_targets/capability_benchmarks/phase9_target_matrix.json")
    )

    keys = [str(item.get("key")) for item in manifest["targets"]]

    assert keys == [
        "repo_demo_api",
        "repo_parser_upload_demo",
        "juice_shop_local",
        "dvwa_local",
        "webgoat_local",
        "crapi_local",
    ]
    assert all("manifest_path" in item for item in manifest["targets"])
    assert any(
        str(item.get("ground_truth_source")) == "pentra_core/dev_targets/capability_benchmarks/dvwa.json"
        for item in manifest["targets"]
    )
    demo_target = next(item for item in manifest["targets"] if str(item.get("key")) == "repo_demo_api")
    assert demo_target["expected_target_profile_keys"] == ["spa_rest_api", "auth_heavy_admin_portal"]
    assert demo_target["pack_coverage_expectations"]["p3a_multi_role_stateful_auth"]["expected_vulnerability_types"] == [
        "idor",
    ]
    assert demo_target["pack_coverage_expectations"]["p3a_access_control_workflow_abuse"]["expected_vulnerability_types"] == [
        "workflow_bypass",
    ]
    assert demo_target["pack_coverage_expectations"]["p3a_disclosure_misconfig_crypto"]["expected_vulnerability_types"] == [
        "openapi_exposure",
        "stack_trace_exposure",
    ]
    parser_target = next(item for item in manifest["targets"] if str(item.get("key")) == "repo_parser_upload_demo")
    assert parser_target["enabled"] is True
    assert parser_target["expected_target_profile_keys"] == ["upload_parser_heavy"]


def test_summarize_phase9_targets_passes_when_three_non_demo_targets_execute() -> None:
    summary = summarize_phase9_targets(
        [
            {"key": "repo_demo_api", "enabled": True, "status": "failed"},
            {"key": "juice_shop_local", "enabled": True, "status": "failed"},
            {"key": "dvwa_local", "enabled": True, "status": "passed"},
            {"key": "webgoat_local", "enabled": True, "status": "failed"},
            {"key": "crapi_local", "enabled": False, "status": "planned"},
        ]
    )

    assert summary["status"] == "passed"
    assert summary["summary"]["non_demo_executed_targets"] == 3
    assert summary["summary"]["launch_failed_targets"] == 0
    assert summary["summary"]["unavailable_targets"] == 0


def test_summarize_phase9_targets_fails_when_enabled_target_is_unavailable() -> None:
    summary = summarize_phase9_targets(
        [
            {"key": "repo_demo_api", "enabled": True, "status": "passed"},
            {"key": "juice_shop_local", "enabled": True, "status": "passed"},
            {"key": "dvwa_local", "enabled": True, "status": "failed"},
            {"key": "webgoat_local", "enabled": True, "status": "unavailable"},
            {"key": "crapi_local", "enabled": False, "status": "planned"},
        ]
    )

    assert summary["status"] == "failed"
    assert summary["summary"]["non_demo_executed_targets"] == 2
    assert summary["summary"]["unavailable_targets"] == 1


def test_summarize_phase9_targets_marks_partial_artifacts_incomplete() -> None:
    summary = summarize_phase9_targets(
        [
            {"key": "repo_demo_api", "enabled": True, "status": "passed"},
            {"key": "juice_shop_local", "enabled": True, "status": "partial"},
            {"key": "dvwa_local", "enabled": True, "status": "passed"},
            {"key": "webgoat_local", "enabled": True, "status": "failed"},
        ]
    )

    assert summary["status"] == "partial"
    assert summary["summary"]["partial_targets"] == 1
    assert summary["summary"]["executed_targets"] == 3


def test_derive_phase9_target_status_marks_nonterminal_runs_partial() -> None:
    status, detail = derive_phase9_target_status(
        [
            {
                "status": "running",
                "partial": True,
                "error": "Scan abc did not reach a terminal state after 180s grace",
            }
        ]
    )

    assert status == "partial"
    assert "did not reach a terminal state" in detail


def test_derive_phase9_target_status_passes_completed_target_bar_runs() -> None:
    status, detail = derive_phase9_target_status(
        [
            {
                "status": "completed",
                "capability_assessment": {"meets_target_bar": True},
            }
        ]
    )

    assert status == "passed"
    assert detail == ""
