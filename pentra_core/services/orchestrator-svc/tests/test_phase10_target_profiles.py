from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_phase10_target_profile_bundle_loads() -> None:
    from app.knowledge.target_profile_registry import load_target_profile_bundle

    bundle = load_target_profile_bundle()

    assert len(bundle.catalog.target_profiles) >= 6
    assert bundle.get_profile("auth_heavy_admin_portal") is not None


def test_phase10_target_profile_classifier_prefers_auth_heavy_admin_portal() -> None:
    from app.knowledge.target_profile_registry import classify_target_profiles

    hypotheses = classify_target_profiles(
        route_groups=["/login", "/admin/users", "/admin/settings", "/api/admin/audit"],
        source_artifact_types=["endpoints", "findings_scored"],
        auth_surface_count=3,
        workflow_edge_count=1,
        capability_pack_keys=["p3a_multi_role_stateful_auth"],
        benchmark_target_keys=["repo_demo_api"],
    )

    assert hypotheses
    assert hypotheses[0].key == "auth_heavy_admin_portal"
    assert hypotheses[0].confidence >= 0.3


def test_phase10_target_profile_classifier_prefers_upload_parser_heavy() -> None:
    from app.knowledge.target_profile_registry import classify_target_profiles

    hypotheses = classify_target_profiles(
        route_groups=["/login", "/portal/upload", "/portal/import/xml", "/portal/attachments"],
        source_artifact_types=["endpoints", "findings_scored"],
        auth_surface_count=1,
        workflow_edge_count=1,
        capability_pack_keys=["p3a_parser_file_abuse"],
        benchmark_target_keys=["repo_parser_upload_demo"],
    )

    assert hypotheses
    assert hypotheses[0].key == "upload_parser_heavy"
    assert hypotheses[0].confidence >= 0.3
