from __future__ import annotations

from pathlib import Path

import yaml


def test_phase10_source_registry_loads_public_first_profile() -> None:
    from app.knowledge.source_registry import load_source_registry

    registry = load_source_registry()

    assert registry.program == "phase10_public_source_first"
    assert registry.default_profile == "public_source_first"
    assert registry.get_profile() is not None
    assert len(registry.sources) >= 8


def test_phase10_source_registry_contains_expected_official_sources() -> None:
    from app.knowledge.source_registry import load_source_registry

    registry = load_source_registry()
    source_keys = {source.key for source in registry.sources}

    assert {
        "mitre_attack_enterprise",
        "owasp_wstg_stable",
        "owasp_asvs",
        "portswigger_web_security_academy",
        "juice_shop_runtime_inventory_local_19_2_1",
        "portswigger_xss_cheat_sheet",
        "owasp_authorization_cheat_sheet",
        "owasp_sql_injection_prevention_cheat_sheet",
        "owasp_query_parameterization_cheat_sheet",
        "portswigger_graphql_api_vulnerabilities",
    } <= source_keys


def test_phase10_runtime_truth_source_is_version_pinned() -> None:
    from app.knowledge.source_registry import load_source_registry

    registry = load_source_registry()
    source = registry.get_source("juice_shop_runtime_inventory_local_19_2_1")

    assert source is not None
    assert source.trust_tier == "runtime_truth"
    assert source.version_policy == "runtime_pinned"
    assert source.target_key == "juice_shop_local"
    assert source.target_version == "19.2.1"
    assert source.artifact_path == ".local/pentra/phase9/juice_shop_challenge_inventory_latest.json"


def test_phase10_active_sources_respect_public_source_first_trust_tiers() -> None:
    from app.knowledge.source_registry import load_source_registry

    registry = load_source_registry()
    active = registry.active_sources()

    assert active
    assert all(
        source.trust_tier in {"official_public", "official_project", "runtime_truth", "community_public"}
        for source in active
    )


def test_phase10_provenance_contract_loads_required_fields() -> None:
    from app.knowledge.source_registry import load_provenance_contract

    contract = load_provenance_contract()

    assert contract.program == "phase10_public_source_first"
    assert "source_key" in contract.required_citation_fields
    assert "target_version" in contract.required_benchmark_truth_fields
    assert "credentialed_optional" in contract.blocked_trust_tiers


def test_phase10_governance_bundle_is_consistent() -> None:
    from app.knowledge.source_registry import load_knowledge_governance_bundle

    bundle = load_knowledge_governance_bundle()

    assert bundle.registry.program == bundle.provenance_contract.program
    assert bundle.registry.get_profile() is not None
    assert bundle.registry.active_sources()
    assert set(bundle.registry.get_profile().optional_trust_tiers) == set(
        bundle.provenance_contract.optional_trust_tiers
    )


def test_phase10_payloads_all_the_things_is_supplemental_community_source() -> None:
    from app.knowledge.source_registry import load_source_registry

    registry = load_source_registry()
    source = registry.get_source("payloads_all_the_things")

    assert source is not None
    assert source.trust_tier == "community_public"
    assert source.access_level == "public"
    assert "payload_variant_enrichment" in source.authority_for


def test_phase10_capability_manifests_reference_official_sources_and_valid_profiles() -> None:
    from pentra_common.schemas.capability import CapabilityManifest

    from app.knowledge.cheatsheet_registry import load_cheatsheet_bundle
    from app.knowledge.source_registry import load_source_registry
    from app.knowledge.target_profile_registry import load_target_profile_bundle

    registry = load_source_registry()
    cheatsheets = load_cheatsheet_bundle()
    target_profiles = load_target_profile_bundle()

    official_source_expectations = {
        "p3a_browser_xss": {
            "owasp_xss_prevention_cheat_sheet",
            "owasp_dom_xss_prevention_cheat_sheet",
            "owasp_input_validation_cheat_sheet",
        },
        "p3a_multi_role_stateful_auth": {
            "owasp_authentication_cheat_sheet",
            "owasp_authorization_cheat_sheet",
            "owasp_session_management_cheat_sheet",
            "owasp_idor_prevention_cheat_sheet",
        },
        "p3a_access_control_workflow_abuse": {
            "owasp_authorization_cheat_sheet",
            "owasp_idor_prevention_cheat_sheet",
        },
        "p3a_injection": {
            "owasp_sql_injection_prevention_cheat_sheet",
            "owasp_query_parameterization_cheat_sheet",
            "owasp_graphql_cheat_sheet",
            "owasp_rest_security_cheat_sheet",
        },
        "p3a_parser_file_abuse": {
            "owasp_file_upload_cheat_sheet",
            "owasp_deserialization_cheat_sheet",
            "owasp_xxe_prevention_cheat_sheet",
        },
        "p3a_disclosure_misconfig_crypto": {
            "owasp_secrets_management_cheat_sheet",
            "owasp_cryptographic_storage_cheat_sheet",
            "owasp_logging_cheat_sheet",
            "owasp_vulnerable_dependency_management_cheat_sheet",
            "owasp_http_headers_cheat_sheet",
        },
    }

    repo_root = Path(__file__).resolve().parents[3]
    manifest_paths = sorted(
        (repo_root / "services" / "worker-svc" / "app" / "engine" / "capabilities").glob(
            "*/capability_manifest.yaml"
        )
    )

    assert manifest_paths

    known_source_keys = {source.key for source in registry.sources}
    known_category_keys = {category.key for category in cheatsheets.catalog.categories}
    known_target_profile_keys = {
        profile.key for profile in target_profiles.catalog.target_profiles
    }

    for path in manifest_paths:
        payload = yaml.safe_load(path.read_text()) or {}
        manifest = CapabilityManifest.model_validate(payload)
        knowledge = manifest.knowledge_dependencies

        assert knowledge.source_registry_keys, manifest.pack_key
        assert knowledge.cheatsheet_category_keys, manifest.pack_key
        assert set(knowledge.source_registry_keys) <= known_source_keys, manifest.pack_key
        assert set(knowledge.cheatsheet_category_keys) <= known_category_keys, manifest.pack_key
        assert set(manifest.target_profile_keys) <= known_target_profile_keys, manifest.pack_key

        official_sources = {
            source_key
            for source_key in knowledge.source_registry_keys
            if registry.get_source(source_key) is not None
            and registry.get_source(source_key).trust_tier in {"official_public", "official_project"}
        }
        assert official_sources, manifest.pack_key

        expected_sources = official_source_expectations[manifest.pack_key]
        assert expected_sources <= set(knowledge.source_registry_keys), manifest.pack_key
