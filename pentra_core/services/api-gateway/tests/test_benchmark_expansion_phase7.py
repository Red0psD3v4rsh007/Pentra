from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
_root_dir = os.path.abspath(os.path.join(_svc_root, "..", "..", ".."))
_scripts_dir = os.path.join(_root_dir, "pentra_core", "scripts", "local")

for path in (_svc_root, _scripts_dir):
    if path not in sys.path:
        sys.path.insert(0, path)


def test_select_asset_ids_cycles_local_asset_pool() -> None:
    from run_phase6_benchmark_matrix import BenchmarkContext, _select_asset_ids

    context = BenchmarkContext(
        project_id="project-1",
        primary_asset_id="asset-a",
        local_asset_ids=("asset-a", "asset-b", "asset-c"),
        web_asset_id="asset-c",
        asset_group_id="group-1",
    )

    assert _select_asset_ids(context, count=5) == [
        "asset-a",
        "asset-b",
        "asset-c",
        "asset-a",
        "asset-b",
    ]


def test_summarize_group_run_rolls_up_multi_scan_metrics() -> None:
    from run_phase6_benchmark_matrix import BenchmarkScenario, _summarize_group_run

    scenario = BenchmarkScenario(
        key="recon_concurrent_5",
        label="Recon / concurrent load x5",
        mode="concurrent",
        scan_type="recon",
        config={"profile_id": "external_web_api_v1"},
        iterations=1,
        timeout_seconds=120,
        concurrency=5,
    )

    bundles = [
        {
            "scan": {
                "id": "scan-1",
                "asset_id": "asset-a",
                "status": "completed",
                "progress": 100,
                "created_at": "2026-03-22T10:00:00+00:00",
                "started_at": "2026-03-22T10:00:01+00:00",
                "completed_at": "2026-03-22T10:00:05+00:00",
            },
            "jobs": [
                {
                    "status": "completed",
                    "worker_id": "worker-recon-1",
                    "scheduled_at": "2026-03-22T10:00:00+00:00",
                    "claimed_at": "2026-03-22T10:00:00.100000+00:00",
                    "started_at": "2026-03-22T10:00:00.400000+00:00",
                }
            ],
            "findings": [
                {
                    "created_at": "2026-03-22T10:00:03+00:00",
                    "verification_state": "verified",
                }
            ],
            "artifacts": [
                {
                    "created_at": "2026-03-22T10:00:02+00:00",
                    "size_bytes": 123,
                    "evidence_count": 2,
                }
            ],
            "attack_graph": {"node_count": 3, "edge_count": 2},
        },
        {
            "scan": {
                "id": "scan-2",
                "asset_id": "asset-b",
                "status": "completed",
                "progress": 100,
                "created_at": "2026-03-22T10:00:00+00:00",
                "started_at": "2026-03-22T10:00:01.500000+00:00",
                "completed_at": "2026-03-22T10:00:06+00:00",
            },
            "jobs": [
                {
                    "status": "completed",
                    "worker_id": "worker-web-1",
                    "scheduled_at": "2026-03-22T10:00:00+00:00",
                    "claimed_at": "2026-03-22T10:00:00.200000+00:00",
                    "started_at": "2026-03-22T10:00:00.600000+00:00",
                }
            ],
            "findings": [],
            "artifacts": [
                {
                    "created_at": "2026-03-22T10:00:02.500000+00:00",
                    "size_bytes": 77,
                    "evidence_count": 1,
                }
            ],
            "attack_graph": {"node_count": 2, "edge_count": 1},
        },
    ]

    summary = _summarize_group_run(
        scenario=scenario,
        group_created_at="2026-03-22T10:00:00+00:00",
        wall_clock_seconds=6.0,
        bundles=bundles,
        worker_before={
            "recon": {"jobs_processed": 10, "jobs_failed": 0},
            "web": {"jobs_processed": 5, "jobs_failed": 0},
        },
        worker_after={
            "recon": {"jobs_processed": 11, "jobs_failed": 0},
            "web": {"jobs_processed": 6, "jobs_failed": 0},
        },
        benchmark_context={
            "mode": "concurrent",
            "asset_ids": ["asset-a", "asset-b"],
            "concurrency": 2,
        },
    )

    assert summary["status"] == "completed"
    assert summary["benchmark_context"]["scan_count"] == 2
    assert summary["benchmark_context"]["concurrency"] == 2
    assert summary["job_counts"]["total"] == 2
    assert summary["output_volume"]["findings"] == 1
    assert summary["output_volume"]["verified_findings"] == 1
    assert summary["output_volume"]["artifacts"] == 2
    assert summary["output_volume"]["artifact_bytes_total"] == 200
    assert summary["output_volume"]["attack_graph_nodes"] == 5
    assert summary["output_volume"]["attack_graph_edges"] == 3
    assert summary["job_metrics"]["avg_queue_delay_seconds"] == 0.15
    assert summary["job_metrics"]["avg_claim_to_start_seconds"] == 0.35
    assert summary["time_to_first_artifact_seconds"] == 2.0
    assert summary["time_to_first_finding_seconds"] == 3.0


def test_aggregate_runs_keeps_group_context() -> None:
    from run_phase6_benchmark_matrix import BenchmarkScenario, _aggregate_runs

    scenario = BenchmarkScenario(
        key="full_multi_asset_batch_direct",
        label="Full / direct multi-asset batch",
        mode="batch_direct",
        scan_type="full",
        config={"profile_id": "external_web_api_v1"},
        iterations=1,
        timeout_seconds=240,
        batch_size=3,
    )
    runs = [
        {
            "total_runtime_seconds": 10.0,
            "execution_runtime_seconds": 8.0,
            "time_to_first_artifact_seconds": 1.0,
            "time_to_first_finding_seconds": 2.0,
            "job_metrics": {
                "first_queue_delay_seconds": 0.1,
                "avg_queue_delay_seconds": 0.2,
                "max_queue_delay_seconds": 0.3,
                "time_to_first_job_start_seconds": 0.4,
                "avg_claim_to_start_seconds": 0.5,
                "max_claim_to_start_seconds": 0.6,
            },
            "output_volume": {
                "artifacts": 9,
                "artifact_bytes_total": 900,
                "findings": 6,
                "verified_findings": 2,
                "evidence": 12,
            },
            "verification_summary": {
                "profile_id": "external_web_api_v1",
                "scan_type": "full",
                "overall": {
                    "total_findings": 6,
                    "verified": 2,
                    "suspected": 0,
                    "detected": 4,
                    "verified_share": 0.333,
                },
                "by_type": [
                    {
                        "vulnerability_type": "sql_injection",
                        "total_findings": 3,
                        "verified": 2,
                        "suspected": 0,
                        "detected": 1,
                        "verified_share": 0.667,
                    }
                ],
            },
            "worker_delta": {"aggregate_jobs_per_second": 1.5},
            "benchmark_context": {
                "mode": "batch_direct",
                "scan_count": 3,
                "batch_request_id": "batch-1",
            },
        }
    ]

    aggregate = _aggregate_runs(scenario, runs)

    assert aggregate["mode"] == "batch_direct"
    assert aggregate["benchmark_context"]["batch_request_id"] == "batch-1"
    assert aggregate["avg_scan_count"] == 3.0
    assert aggregate["avg_total_runtime_seconds"] == 10.0
    assert aggregate["avg_verified_share"] == 0.333
    assert aggregate["verification_summary"]["by_type"][0]["vulnerability_type"] == "sql_injection"


def test_build_verification_summary_reports_share_by_type() -> None:
    from run_phase6_benchmark_matrix import _build_verification_summary

    summary = _build_verification_summary(
        findings=[
            {"vulnerability_type": "sql_injection", "verification_state": "verified"},
            {"vulnerability_type": "sql_injection", "verification_state": "detected"},
            {"vulnerability_type": "auth_bypass", "verification_state": "verified"},
        ],
        profile_id="external_web_api_v1",
        scan_type="full",
    )

    assert summary["profile_id"] == "external_web_api_v1"
    assert summary["overall"]["verified_share"] == 0.667
    assert summary["by_type"][0]["vulnerability_type"] == "auth_bypass"
    sqli = next(item for item in summary["by_type"] if item["vulnerability_type"] == "sql_injection")
    assert sqli["verified_share"] == 0.5
