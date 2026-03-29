from __future__ import annotations


def test_phase10_ontology_bundle_loads() -> None:
    from app.knowledge.ontology_registry import load_ontology_bundle

    bundle = load_ontology_bundle()

    assert bundle.challenge_families.families
    assert bundle.attack_primitives.attack_primitives
    assert bundle.capability_graphs.capability_graphs


def test_phase10_ontology_covers_all_runtime_juice_shop_categories() -> None:
    from app.knowledge.ontology_registry import load_ontology_bundle

    bundle = load_ontology_bundle()
    runtime_categories = {
        "Broken Access Control",
        "Broken Anti Automation",
        "Broken Authentication",
        "Cryptographic Issues",
        "Improper Input Validation",
        "Injection",
        "Insecure Deserialization",
        "Miscellaneous",
        "Observability Failures",
        "Security Misconfiguration",
        "Security through Obscurity",
        "Sensitive Data Exposure",
        "Unvalidated Redirects",
        "Vulnerable Components",
        "XSS",
        "XXE",
    }
    mapped = {
        label
        for family in bundle.challenge_families.families
        for label in family.category_labels
    }

    assert runtime_categories <= mapped


def test_phase10_xss_family_is_browser_first() -> None:
    from app.knowledge.ontology_registry import load_ontology_bundle

    bundle = load_ontology_bundle()
    family = next(f for f in bundle.challenge_families.families if f.key == "xss")

    assert "dom_xss_browser_probe" in family.attack_primitive_keys
    assert "browser_execution_xss" in family.proof_contract_keys
    assert "map_client_side_sinks" in family.planner_action_keys


def test_phase10_juice_shop_role_model_contains_customer_and_admin() -> None:
    from app.knowledge.ontology_registry import load_ontology_bundle

    bundle = load_ontology_bundle()
    role_model = next(role for role in bundle.role_models.role_models if role.key == "juice_shop_local_roles")
    role_keys = {role.key for role in role_model.roles}

    assert {"anonymous", "customer", "admin"} <= role_keys


def test_phase10_capability_graph_edges_reference_valid_strategy_paths() -> None:
    from app.knowledge.ontology_registry import load_ontology_bundle

    bundle = load_ontology_bundle()
    graph = next(graph for graph in bundle.capability_graphs.capability_graphs if graph.key == "juice_shop_local_web_graph")
    edge_pairs = {(edge.source_key, edge.target_key) for edge in graph.edges}

    assert ("xss", "dom_xss_browser_probe") in edge_pairs
    assert ("dom_xss_browser_probe", "browser_execution_xss") in edge_pairs
    assert ("juice_shop_local_roles", "compare_role_access") in edge_pairs


def test_phase10_capability_graphs_cover_real_target_profiles() -> None:
    from app.knowledge.ontology_registry import load_ontology_bundle

    bundle = load_ontology_bundle()
    graph_map = {graph.key: graph for graph in bundle.capability_graphs.capability_graphs}

    assert {
        "spa_rest_api_capability_graph",
        "traditional_server_rendered_capability_graph",
        "graphql_heavy_application_capability_graph",
        "auth_heavy_admin_portal_capability_graph",
        "workflow_heavy_commerce_capability_graph",
        "upload_parser_heavy_capability_graph",
    } <= set(graph_map)
    assert graph_map["spa_rest_api_capability_graph"].target_profile_keys == ["spa_rest_api"]
    assert graph_map["auth_heavy_admin_portal_capability_graph"].target_profile_keys == [
        "auth_heavy_admin_portal"
    ]
    assert graph_map["upload_parser_heavy_capability_graph"].benchmark_target_keys == [
        "repo_parser_upload_demo"
    ]


def test_phase10_ontology_supports_category_to_action_lookup() -> None:
    from app.knowledge.ontology_registry import load_ontology_bundle

    bundle = load_ontology_bundle()
    mapping = bundle.category_action_map("juice_shop_local")

    assert "XSS" in mapping
    assert "Broken Access Control" in mapping
    assert "map_client_side_sinks" in mapping["XSS"]
    assert "compare_role_access" in mapping["Broken Access Control"]
