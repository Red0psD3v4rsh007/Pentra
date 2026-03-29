from __future__ import annotations


def test_phase10_cheatsheet_bundle_loads() -> None:
    from app.knowledge.cheatsheet_registry import load_cheatsheet_bundle

    bundle = load_cheatsheet_bundle()

    assert bundle.catalog.categories
    assert len(bundle.catalog.categories) >= 6


def test_phase10_browser_xss_cheatsheet_category_is_officially_anchored() -> None:
    from app.knowledge.cheatsheet_registry import load_cheatsheet_bundle

    bundle = load_cheatsheet_bundle()
    category = bundle.get_category("browser_xss")

    assert category is not None
    assert "xss" in category.ontology_family_keys
    assert "p3a_browser_xss" in category.phase3_pack_keys
    assert {entry.source_key for entry in category.entries} >= {
        "portswigger_xss_cheat_sheet",
        "owasp_xss_prevention_cheat_sheet",
        "owasp_dom_xss_prevention_cheat_sheet",
    }


def test_phase10_injection_cheatsheet_category_is_officially_anchored() -> None:
    from app.knowledge.cheatsheet_registry import load_cheatsheet_bundle

    bundle = load_cheatsheet_bundle()
    category = bundle.get_category("injection_and_query_abuse")

    assert category is not None
    assert "injection" in category.ontology_family_keys
    assert "p3a_injection" in category.phase3_pack_keys
    assert {entry.source_key for entry in category.entries} >= {
        "owasp_wstg_stable",
        "portswigger_sql_injection_cheat_sheet",
        "owasp_sql_injection_prevention_cheat_sheet",
        "owasp_query_parameterization_cheat_sheet",
        "owasp_input_validation_cheat_sheet",
    }


def test_phase10_graphql_api_cheatsheet_category_is_officially_anchored() -> None:
    from app.knowledge.cheatsheet_registry import load_cheatsheet_bundle

    bundle = load_cheatsheet_bundle()
    category = bundle.get_category("graphql_and_api_abuse")

    assert category is not None
    assert "p3a_injection" in category.phase3_pack_keys
    assert {entry.source_key for entry in category.entries} >= {
        "owasp_graphql_cheat_sheet",
        "owasp_rest_security_cheat_sheet",
        "portswigger_graphql_api_vulnerabilities",
    }


def test_phase10_community_sources_are_supplemental_only() -> None:
    from app.knowledge.cheatsheet_registry import load_cheatsheet_bundle
    from app.knowledge.source_registry import load_source_registry

    bundle = load_cheatsheet_bundle()
    registry = load_source_registry()

    for category in bundle.catalog.categories:
        authoritative_entries = 0
        for entry in category.entries:
            source = registry.get_source(entry.source_key)
            assert source is not None
            if source.trust_tier == "community_public":
                assert entry.trust_role == "supplemental"
            if entry.trust_role == "authoritative":
                authoritative_entries += 1
        assert authoritative_entries >= 1


def test_phase10_cheatsheet_registry_supports_family_and_pack_lookup() -> None:
    from app.knowledge.cheatsheet_registry import load_cheatsheet_bundle

    bundle = load_cheatsheet_bundle()

    xss_categories = {category.key for category in bundle.categories_for_family("xss")}
    auth_pack_categories = {category.key for category in bundle.categories_for_pack("p3a_multi_role_stateful_auth")}

    assert "browser_xss" in xss_categories
    assert {"authentication_and_sessions", "authorization_and_access_control"} <= auth_pack_categories
