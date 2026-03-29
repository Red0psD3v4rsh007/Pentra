from __future__ import annotations

import json
from pathlib import Path

import pytest

from pentra_core.scripts.local.generate_target_bar_gap_report import generate_report_markdown
from pentra_core.scripts.local.proof_contract import (
    ProofContractError,
    stamp_proof_payload,
    validate_proof_bundle,
)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def _scenario_payload() -> dict[str, object]:
    scenario = {
        "scenario_key": "recon_web_api_v1",
        "status": "completed",
        "progress": 100,
        "job_provenance_counts": {"live": 2},
        "verification_summary": {
            "overall": {
                "total_findings": 0,
                "verified": 0,
                "detected": 0,
                "suspected": 0,
                "verified_share": 0.0,
            },
            "by_type": [],
        },
    }
    full_summary = {
        "overall": {
            "total_findings": 6,
            "verified": 4,
            "detected": 2,
            "suspected": 0,
            "verified_share": 0.667,
        },
        "by_type": [
            {"vulnerability_type": "auth_bypass", "verified": 1, "total_findings": 1, "verified_share": 1.0},
            {"vulnerability_type": "idor", "verified": 1, "total_findings": 1, "verified_share": 1.0},
            {"vulnerability_type": "workflow_bypass", "verified": 1, "total_findings": 1, "verified_share": 1.0},
            {"vulnerability_type": "sql_injection", "verified": 1, "total_findings": 2, "verified_share": 0.5},
        ],
    }
    return {
        "status": "passed",
        "scenarios": [
            scenario,
            {
                "scenario_key": "vuln_web_api_v1",
                "status": "completed",
                "progress": 100,
                "job_provenance_counts": {"live": 11, "derived": 2},
                "verification_summary": full_summary,
            },
            {
                "scenario_key": "full_safe_verify_web_api_v1",
                "status": "completed",
                "progress": 100,
                "job_provenance_counts": {"live": 11, "derived": 2},
                "verification_summary": full_summary,
            },
            {
                "scenario_key": "full_stateful_web_api_v1",
                "status": "completed",
                "progress": 100,
                "job_provenance_counts": {"live": 14, "derived": 2},
                "verification_summary": full_summary,
            },
        ],
    }


def _chaos_payload() -> dict[str, object]:
    return {
        "status": "passed",
        "summary": {"passed": 5, "failed": 0},
        "scenarios": [
            {
                "scenario_key": "worker_death_recovery",
                "status": "passed",
                "detail": {"recovery_resume_seconds": 9.8},
            },
        ],
    }


def _benchmark_payload() -> dict[str, object]:
    def benchmark_item(key: str, *, verified_share: float, total_runtime: float = 1.5) -> dict[str, object]:
        return {
            "scenario_key": key,
            "avg_total_runtime_seconds": total_runtime,
            "avg_queue_delay_seconds": 0.01,
            "avg_time_to_first_job_start_seconds": 0.02,
            "avg_claim_to_start_seconds": 0.01,
            "avg_verified_share": verified_share,
            "verification_summary": {
                "overall": {
                    "total_findings": 6 if verified_share else 0,
                    "verified": 4 if verified_share else 0,
                    "detected": 2 if verified_share else 0,
                    "suspected": 0,
                    "verified_share": verified_share,
                },
                "by_type": [],
            },
        }

    return {
        "status": "passed",
        "scenario_benchmarks": [
            benchmark_item("recon_web_api_v1", verified_share=0.0, total_runtime=1.8),
            benchmark_item("vuln_web_api_v1", verified_share=0.667, total_runtime=8.9),
            benchmark_item("full_web_api_v1", verified_share=0.667, total_runtime=9.0),
            benchmark_item("full_stateful_web_api_v1", verified_share=0.667, total_runtime=9.3),
            benchmark_item("full_web_local_web_app", verified_share=0.667, total_runtime=11.0),
            benchmark_item("full_multi_asset_batch_direct", verified_share=0.667, total_runtime=25.5),
            benchmark_item("full_multi_asset_batch_group", verified_share=0.667, total_runtime=24.4),
            benchmark_item("recon_concurrent_1", verified_share=0.0, total_runtime=1.8),
            benchmark_item("recon_concurrent_5", verified_share=0.0, total_runtime=5.0),
            benchmark_item("recon_concurrent_10", verified_share=0.0, total_runtime=8.0),
        ],
        "cold_start_probe": {
            "probe_mode": "true_cold",
            "no_prewarm": {"image_reset": {"secsi/ffuf:latest": True}},
            "with_prewarm": {"image_reset": {"secsi/ffuf:latest": True}},
        },
    }


def _stamp(payload: dict[str, object], *, artifact_kind: str, root_dir: Path) -> dict[str, object]:
    return stamp_proof_payload(
        payload,
        artifact_kind=artifact_kind,
        phase="test",
        script_path="tests/test_release_evidence_phase7.py",
        root_dir=root_dir,
        environment_context={
            "api_base_url": "http://127.0.0.1:8000",
            "orchestrator_base_url": "http://127.0.0.1:8001",
            "demo_target_url": "http://127.0.0.1:8088",
        },
        run_id=f"{artifact_kind}-run",
    )


def test_validate_proof_bundle_rejects_stale_artifact(tmp_path: Path) -> None:
    root_dir = Path(__file__).resolve().parents[4]
    scenario_path = tmp_path / "scenario.json"
    chaos_path = tmp_path / "chaos.json"
    benchmark_path = tmp_path / "benchmark.json"

    scenario = _stamp(_scenario_payload(), artifact_kind="scenario_matrix", root_dir=root_dir)
    chaos = _stamp(_chaos_payload(), artifact_kind="chaos_matrix", root_dir=root_dir)
    benchmark = _stamp(_benchmark_payload(), artifact_kind="benchmark_matrix", root_dir=root_dir)

    scenario["proof_metadata"]["generated_at"] = "2000-01-01T00:00:00+00:00"
    scenario["generated_at"] = "2000-01-01T00:00:00+00:00"

    _write_json(scenario_path, scenario)
    _write_json(chaos_path, chaos)
    _write_json(benchmark_path, benchmark)

    with pytest.raises(ProofContractError, match="stale"):
        validate_proof_bundle(
            {
                "scenario": (scenario_path, "scenario_matrix"),
                "chaos": (chaos_path, "chaos_matrix"),
                "benchmark": (benchmark_path, "benchmark_matrix"),
            },
            max_age_seconds=60,
        )


def test_validate_proof_bundle_rejects_inconsistent_git_revision(tmp_path: Path) -> None:
    root_dir = Path(__file__).resolve().parents[4]
    scenario_path = tmp_path / "scenario.json"
    chaos_path = tmp_path / "chaos.json"
    benchmark_path = tmp_path / "benchmark.json"

    scenario = _stamp(_scenario_payload(), artifact_kind="scenario_matrix", root_dir=root_dir)
    chaos = _stamp(_chaos_payload(), artifact_kind="chaos_matrix", root_dir=root_dir)
    benchmark = _stamp(_benchmark_payload(), artifact_kind="benchmark_matrix", root_dir=root_dir)
    benchmark["proof_metadata"]["git"]["revision"] = "deadbeef"
    benchmark["git_revision"] = "deadbeef"

    _write_json(scenario_path, scenario)
    _write_json(chaos_path, chaos)
    _write_json(benchmark_path, benchmark)

    with pytest.raises(ProofContractError, match="git revision"):
        validate_proof_bundle(
            {
                "scenario": (scenario_path, "scenario_matrix"),
                "chaos": (chaos_path, "chaos_matrix"),
                "benchmark": (benchmark_path, "benchmark_matrix"),
            },
            max_age_seconds=3600,
        )


def test_generate_report_markdown_includes_freshness_contract(tmp_path: Path) -> None:
    root_dir = Path(__file__).resolve().parents[4]
    scenario_path = tmp_path / "scenario.json"
    chaos_path = tmp_path / "chaos.json"
    benchmark_path = tmp_path / "benchmark.json"

    _write_json(scenario_path, _stamp(_scenario_payload(), artifact_kind="scenario_matrix", root_dir=root_dir))
    _write_json(chaos_path, _stamp(_chaos_payload(), artifact_kind="chaos_matrix", root_dir=root_dir))
    _write_json(benchmark_path, _stamp(_benchmark_payload(), artifact_kind="benchmark_matrix", root_dir=root_dir))

    bundle = validate_proof_bundle(
        {
            "scenario": (scenario_path, "scenario_matrix"),
            "chaos": (chaos_path, "chaos_matrix"),
            "benchmark": (benchmark_path, "benchmark_matrix"),
        },
        max_age_seconds=3600,
    )

    markdown = generate_report_markdown(bundle=bundle, freshness_window_seconds=3600)

    assert "## Proof Freshness" in markdown
    assert "common git revision" in markdown
    assert "### `G8` Release-proof freshness and consistency gap" in markdown
    assert "Status: `closed`" in markdown
    assert "4/6 verified" in markdown
