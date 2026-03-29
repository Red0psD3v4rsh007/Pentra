from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(_svc_root)))
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)


def test_phase10_disclosure_benchmark_assessment_uses_pack_specific_expectations() -> None:
    from pentra_core.scripts.local.validate_phase10_disclosure_benchmarks import _evaluate_disclosure_assessment

    assessment = _evaluate_disclosure_assessment(
        target_spec={
            "pack_coverage_expectations": {
                "p3a_disclosure_misconfig_crypto": {
                    "expected_vulnerability_types": [
                        "openapi_exposure",
                        "stack_trace_exposure",
                        "sql_injection",
                    ]
                }
            }
        },
        discovery={
            "disclosure_candidates": [
                {"vulnerability_type": "openapi_exposure"},
                {"vulnerability_type": "stack_trace_exposure"},
            ],
            "disclosure_misconfig_crypto_capability": {
                "candidate_count": 2,
                "planner_hook_count": 2,
                "route_assessment_counts": {"negative_evidence_routes": 1},
            },
        },
    )

    assert assessment["scope"] == "disclosure_only"
    assert assessment["expected_vulnerability_types"] == ["openapi_exposure", "stack_trace_exposure"]
    assert assessment["detected_expected_types"] == ["openapi_exposure", "stack_trace_exposure"]
    assert assessment["missed_expected_types"] == []
    assert assessment["detected_recall"] == 1.0
    assert assessment["meets_target_bar"] is True
