from __future__ import annotations


def test_phase10_corpus_index_loads() -> None:
    from app.knowledge.corpus_registry import load_corpus_index

    index = load_corpus_index()

    assert index.program == "phase10_public_source_first"
    assert index.phase == 1
    assert len(index.raw_manifest_paths) >= 15
    assert len(index.normalized_document_paths) >= 15


def test_phase10_corpus_bundle_loads_and_matches_source_governance() -> None:
    from app.knowledge.corpus_registry import load_corpus_bundle

    bundle = load_corpus_bundle()

    assert bundle.manifests
    assert bundle.documents
    assert {manifest.source_key for manifest in bundle.manifests} == {
        document.source_key for document in bundle.documents
    }


def test_phase10_runtime_summary_matches_local_juice_shop_truth() -> None:
    from app.knowledge.corpus_registry import load_corpus_bundle

    bundle = load_corpus_bundle()
    document = next(
        document
        for document in bundle.documents
        if document.key == "juice_shop_runtime_inventory_local_19_2_1"
    )

    benchmark_fact = next(
        fact for fact in document.facts if fact.fact_key == "juice_shop_local_19_2_1_benchmark_truth"
    )
    category_fact = next(
        fact for fact in document.facts if fact.fact_key == "juice_shop_local_19_2_1_category_counts"
    )
    difficulty_fact = next(
        fact for fact in document.facts if fact.fact_key == "juice_shop_local_19_2_1_difficulty_counts"
    )

    assert benchmark_fact.data["target_version"] == "19.2.1"
    assert benchmark_fact.data["total_challenges"] == 111
    assert category_fact.data["category_count"] == 16
    assert category_fact.data["category_counts"]["Sensitive Data Exposure"] == 16
    assert category_fact.data["category_counts"]["XSS"] == 9
    assert difficulty_fact.data["difficulty_counts"]["4"] == 25


def test_phase10_portswigger_summary_contains_hard_web_topics() -> None:
    from app.knowledge.corpus_registry import load_corpus_bundle

    bundle = load_corpus_bundle()
    document = next(
        document
        for document in bundle.documents
        if document.key == "portswigger_web_security_academy"
    )
    fact = next(
        fact for fact in document.facts if fact.fact_key == "portswigger_web_security_academy_topic_families"
    )
    topics = set(fact.data["priority_topics"])

    assert {"Cross-site scripting", "DOM-based vulnerabilities", "Business logic vulnerabilities"} <= topics


def test_phase10_injection_summaries_cover_parameterization_and_graphql() -> None:
    from app.knowledge.corpus_registry import load_corpus_bundle

    bundle = load_corpus_bundle()
    sqli_doc = next(
        document
        for document in bundle.documents
        if document.key == "owasp_sql_injection_prevention_cheat_sheet"
    )
    graphql_doc = next(
        document
        for document in bundle.documents
        if document.key == "portswigger_graphql_api_vulnerabilities"
    )

    sqli_fact = next(
        fact
        for fact in sqli_doc.facts
        if fact.fact_key == "owasp_sql_injection_prevention_primary_defenses"
    )
    graphql_fact = next(
        fact
        for fact in graphql_doc.facts
        if fact.fact_key == "portswigger_graphql_endpoint_discovery_patterns"
    )

    assert "parameterized_queries" in sqli_fact.data["primary_controls"]
    assert "discover_graphql_endpoint" in graphql_fact.data["discovery_sequence"]


def test_phase10_remaining_category_summaries_cover_auth_parser_and_disclosure() -> None:
    from app.knowledge.corpus_registry import load_corpus_bundle

    bundle = load_corpus_bundle()
    documents = {document.key: document for document in bundle.documents}

    assert {
        "owasp_authentication_cheat_sheet",
        "owasp_authorization_cheat_sheet",
        "owasp_session_management_cheat_sheet",
        "owasp_input_validation_cheat_sheet",
        "owasp_file_upload_cheat_sheet",
        "owasp_deserialization_cheat_sheet",
        "owasp_xxe_prevention_cheat_sheet",
        "owasp_secrets_management_cheat_sheet",
        "owasp_cryptographic_storage_cheat_sheet",
        "owasp_logging_cheat_sheet",
        "owasp_http_headers_cheat_sheet",
        "owasp_wstg_configuration_deployment_management",
        "owasp_wstg_error_handling",
        "owasp_wstg_weak_cryptography",
        "owasp_vulnerable_dependency_management_cheat_sheet",
    } <= set(documents)

    auth_fact = next(
        fact
        for fact in documents["owasp_authentication_cheat_sheet"].facts
        if fact.fact_key == "owasp_authentication_general_controls"
    )
    upload_fact = next(
        fact
        for fact in documents["owasp_file_upload_cheat_sheet"].facts
        if fact.fact_key == "owasp_file_upload_defense_in_depth"
    )
    headers_fact = next(
        fact
        for fact in documents["owasp_http_headers_cheat_sheet"].facts
        if fact.fact_key == "owasp_http_headers_baseline_controls"
    )
    error_fact = next(
        fact
        for fact in documents["owasp_wstg_error_handling"].facts
        if fact.fact_key == "owasp_wstg_error_handling_replay_patterns"
    )
    deployment_fact = next(
        fact
        for fact in documents["owasp_wstg_configuration_deployment_management"].facts
        if fact.fact_key == "owasp_wstg_config_deployment_surface_review"
    )
    weak_crypto_fact = next(
        fact
        for fact in documents["owasp_wstg_weak_cryptography"].facts
        if fact.fact_key == "owasp_wstg_weak_crypto_review_patterns"
    )
    dependency_fact = next(
        fact
        for fact in documents["owasp_vulnerable_dependency_management_cheat_sheet"].facts
        if fact.fact_key == "owasp_dependency_management_response_paths"
    )

    assert "throttling_and_lockout" in auth_fact.data["high_signal_auth_workflows"]
    assert "storage_outside_webroot" in upload_fact.data["high_signal_upload_controls"]
    assert "strict_transport_security" in headers_fact.data["high_signal_header_controls"]
    assert "exception_trigger_reproduction" in error_fact.data["high_signal_error_disclosure_checks"]
    assert "backup_and_unreferenced_files" in deployment_fact.data["high_signal_config_surfaces"]
    assert "key_and_token_material_exposure_review" in weak_crypto_fact.data["high_signal_crypto_review_controls"]
    assert "component_truth_before_promotion" in dependency_fact.data["high_signal_dependency_controls"]


def test_phase10_all_phase1_citations_use_allowed_trust_tiers() -> None:
    from app.knowledge.corpus_registry import load_corpus_bundle
    from app.knowledge.source_registry import load_provenance_contract

    bundle = load_corpus_bundle()
    contract = load_provenance_contract()
    allowed = set(contract.allowed_trust_tiers) | set(contract.optional_trust_tiers)

    for manifest in bundle.manifests:
        for citation in manifest.citations:
            assert citation.trust_tier in allowed

    for document in bundle.documents:
        for fact in document.facts:
            for citation in fact.citations:
                assert citation.trust_tier in allowed
