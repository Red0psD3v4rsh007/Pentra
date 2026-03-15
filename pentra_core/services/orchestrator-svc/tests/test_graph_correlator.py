"""MOD-08 Phase 1 — Graph Correlator tests.

Validates inference rules, edge addition, and path expansion.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_graph_correlator.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


# ═══════════════════════════════════════════════════════════════════
# 1. Correlation rules data
# ═══════════════════════════════════════════════════════════════════


def test_rules_exist():
    from app.engine.graph_correlator import CORRELATION_RULES
    assert len(CORRELATION_RULES) >= 5


def test_rules_have_names():
    from app.engine.graph_correlator import CORRELATION_RULES
    names = {r.name for r in CORRELATION_RULES}
    assert "credential_reuse" in names
    assert "config_leak_endpoints" in names
    assert "cloud_privesc" in names
    assert "service_chaining" in names
    assert "vuln_credential_extraction" in names


def test_rules_have_valid_edge_types():
    from app.engine.graph_correlator import CORRELATION_RULES
    valid = {"discovery", "exploit", "credential_usage", "lateral_movement", "privilege_escalation"}
    for r in CORRELATION_RULES:
        assert r.edge_type in valid, f"Rule {r.name} has invalid edge_type: {r.edge_type}"


# ═══════════════════════════════════════════════════════════════════
# 2. Credential reuse correlation
# ═══════════════════════════════════════════════════════════════════


def test_credential_reuse_lateral_movement():
    """Credential nodes should create lateral_movement edges to services."""
    from app.engine.attack_graph_builder import AttackGraph, AttackNode
    from app.engine.graph_correlator import GraphCorrelator

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="c1", node_type="credential", label="admin:pass123",
                          artifact_ref="r1", properties={"artifact_id": "a1"}))
    g.add_node(AttackNode(id="s1", node_type="service", label="ssh:22",
                          artifact_ref="r2", properties={"artifact_id": "a2"}))
    g.add_node(AttackNode(id="s2", node_type="service", label="rdp:3389",
                          artifact_ref="r3", properties={"artifact_id": "a3"}))

    correlator = GraphCorrelator()
    new_edges = correlator.correlate(g)

    lateral = [e for e in new_edges if e.edge_type == "lateral_movement"
               and e.properties.get("correlation_rule") == "credential_reuse"]
    assert len(lateral) >= 2  # c1→s1, c1→s2


# ═══════════════════════════════════════════════════════════════════
# 3. Config leak → hidden endpoints
# ═══════════════════════════════════════════════════════════════════


def test_config_leak_discovers_endpoints():
    """LFI vulnerability should infer discovery edges to endpoints."""
    from app.engine.attack_graph_builder import AttackGraph, AttackNode
    from app.engine.graph_correlator import GraphCorrelator

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="v1", node_type="vulnerability", label="LFI on /etc/passwd",
                          artifact_ref="r1", properties={"artifact_type": "lfi"}))
    g.add_node(AttackNode(id="e1", node_type="endpoint", label="/admin/config",
                          artifact_ref="r2", properties={}))

    correlator = GraphCorrelator()
    new_edges = correlator.correlate(g)

    disco = [e for e in new_edges if e.edge_type == "discovery"
             and e.properties.get("correlation_rule") == "config_leak_endpoints"]
    assert len(disco) >= 1


# ═══════════════════════════════════════════════════════════════════
# 4. Cloud privilege escalation
# ═══════════════════════════════════════════════════════════════════


def test_cloud_privesc_from_api_key():
    """API key credential should infer privilege escalation to privilege nodes."""
    from app.engine.attack_graph_builder import AttackGraph, AttackNode
    from app.engine.graph_correlator import GraphCorrelator

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="c1", node_type="credential", label="AWS API Key leak",
                          artifact_ref="r1", properties={"artifact_id": "a1"}))
    g.add_node(AttackNode(id="p1", node_type="privilege", label="cloud admin",
                          artifact_ref="r2", properties={"artifact_type": "privilege_escalation"}))

    correlator = GraphCorrelator()
    new_edges = correlator.correlate(g)

    privesc = [e for e in new_edges if e.edge_type == "privilege_escalation"
               and e.properties.get("correlation_rule") == "cloud_privesc"]
    assert len(privesc) >= 1


# ═══════════════════════════════════════════════════════════════════
# 5. Service chaining
# ═══════════════════════════════════════════════════════════════════


def test_service_chaining_lateral():
    """Multiple services should get lateral_movement edges between them."""
    from app.engine.attack_graph_builder import AttackGraph, AttackNode
    from app.engine.graph_correlator import GraphCorrelator

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="s1", node_type="service", label="http:80",
                          artifact_ref="r1", properties={"artifact_id": "a1", "host": "example.com"}))
    g.add_node(AttackNode(id="s2", node_type="service", label="mysql:3306",
                          artifact_ref="r2", properties={"artifact_id": "a2", "host": "example.com"}))

    correlator = GraphCorrelator()
    new_edges = correlator.correlate(g)

    chain = [e for e in new_edges if e.properties.get("correlation_rule") == "service_chaining"]
    assert len(chain) >= 1


def test_asset_lateral_requires_network_context():
    from app.engine.attack_graph_builder import AttackGraph, AttackNode
    from app.engine.graph_correlator import GraphCorrelator

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="a1", node_type="asset", label="example.com", artifact_ref="r1"))
    g.add_node(AttackNode(id="a2", node_type="asset", label="api.example.com", artifact_ref="r2"))

    correlator = GraphCorrelator()
    new_edges = correlator.correlate(g)

    lateral = [e for e in new_edges if e.properties.get("correlation_rule") == "asset_lateral"]
    assert lateral == []


def test_privilege_chain_only_escalates_forward():
    from app.engine.attack_graph_builder import AttackGraph, AttackNode
    from app.engine.graph_correlator import GraphCorrelator

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(
        AttackNode(
            id="p1",
            node_type="privilege",
            label="database access",
            artifact_ref="r1",
            properties={"artifact_type": "database_access", "target": "example.com"},
        )
    )
    g.add_node(
        AttackNode(
            id="p2",
            node_type="privilege",
            label="shell access",
            artifact_ref="r2",
            properties={"artifact_type": "shell_access", "target": "example.com"},
        )
    )

    correlator = GraphCorrelator()
    new_edges = correlator.correlate(g)

    forward = [e for e in new_edges if e.source == "p1" and e.target == "p2"]
    backward = [e for e in new_edges if e.source == "p2" and e.target == "p1"]
    assert len(forward) >= 1
    assert backward == []


# ═══════════════════════════════════════════════════════════════════
# 6. Vuln → credential extraction
# ═══════════════════════════════════════════════════════════════════


def test_vuln_credential_extraction():
    """SQL injection should infer exploit edge to credentials."""
    from app.engine.attack_graph_builder import AttackGraph, AttackNode
    from app.engine.graph_correlator import GraphCorrelator

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="v1", node_type="vulnerability", label="SQL Injection",
                          artifact_ref="r1", properties={"artifact_type": "sql_injection"}))
    g.add_node(AttackNode(id="c1", node_type="credential", label="db_creds",
                          artifact_ref="r2", properties={"artifact_id": "a2"}))

    correlator = GraphCorrelator()
    new_edges = correlator.correlate(g)

    exploit = [e for e in new_edges if e.properties.get("correlation_rule") == "vuln_credential_extraction"]
    assert len(exploit) >= 1
    assert exploit[0].edge_type == "exploit"


# ═══════════════════════════════════════════════════════════════════
# 7. Edge deduplication
# ═══════════════════════════════════════════════════════════════════


def test_no_duplicate_edges():
    """Correlator must not add edges that already exist."""
    from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge
    from app.engine.graph_correlator import GraphCorrelator

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="s1", node_type="service", label="a",
                          artifact_ref="r1", properties={"artifact_id": "a1"}))
    g.add_node(AttackNode(id="s2", node_type="service", label="b",
                          artifact_ref="r2", properties={"artifact_id": "a2"}))
    g.add_edge(AttackEdge(source="s1", target="s2", edge_type="lateral_movement"))

    correlator = GraphCorrelator()
    new_edges = correlator.correlate(g)

    # s1→s2 already exists, correlator should not duplicate it
    s1_s2 = [e for e in new_edges if e.source == "s1" and e.target == "s2"]
    assert len(s1_s2) == 0


def test_no_self_edges():
    """Correlator must not create self-loops."""
    from app.engine.attack_graph_builder import AttackGraph, AttackNode
    from app.engine.graph_correlator import GraphCorrelator

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="s1", node_type="service", label="http",
                          artifact_ref="r1", properties={"artifact_id": "a1"}))

    correlator = GraphCorrelator()
    new_edges = correlator.correlate(g)

    self_loops = [e for e in new_edges if e.source == e.target]
    assert len(self_loops) == 0


# ═══════════════════════════════════════════════════════════════════
# 8. Filter matching
# ═══════════════════════════════════════════════════════════════════


def test_filter_artifact_type_contains():
    from app.engine.attack_graph_builder import AttackNode
    from app.engine.graph_correlator import GraphCorrelator

    c = GraphCorrelator()
    node = AttackNode(id="n", node_type="vulnerability", label="test",
                      artifact_ref="", properties={"artifact_type": "sql_injection"})

    assert c._matches_filter(node, {"artifact_type_contains": ["sql_injection"]})
    assert not c._matches_filter(node, {"artifact_type_contains": ["xss"]})


def test_filter_label_contains():
    from app.engine.attack_graph_builder import AttackNode
    from app.engine.graph_correlator import GraphCorrelator

    c = GraphCorrelator()
    node = AttackNode(id="n", node_type="credential", label="AWS API Key found",
                      artifact_ref="", properties={})

    assert c._matches_filter(node, {"label_contains": ["api_key", "aws"]})
    assert not c._matches_filter(node, {"label_contains": ["ssh"]})


def test_filter_empty_matches_all():
    from app.engine.attack_graph_builder import AttackNode
    from app.engine.graph_correlator import GraphCorrelator

    c = GraphCorrelator()
    node = AttackNode(id="n", node_type="asset", label="any", artifact_ref="", properties={})
    assert c._matches_filter(node, {})


# ═══════════════════════════════════════════════════════════════════
# 9. Full end-to-end: correlation expands paths
# ═══════════════════════════════════════════════════════════════════


def test_correlation_expands_attack_paths():
    """Full e2e: correlated edges should create additional attack paths."""
    from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge
    from app.engine.path_enumerator import PathEnumerator
    from app.engine.graph_correlator import GraphCorrelator

    g = AttackGraph(scan_id="s", tenant_id="t")

    # Basic chain: entrypoint → asset → service → vuln
    g.add_node(AttackNode(id="ep", node_type="entrypoint", label="attacker", artifact_ref=""))
    g.add_node(AttackNode(id="a1", node_type="asset", label="web-server",
                          artifact_ref="r1", properties={"artifact_id": "x1"}))
    g.add_node(AttackNode(id="s1", node_type="service", label="http:80",
                          artifact_ref="r2", properties={"artifact_id": "x2"}))
    g.add_node(AttackNode(id="v1", node_type="vulnerability", label="SQL Injection",
                          artifact_ref="r3", properties={"artifact_type": "sql_injection"}))
    g.add_node(AttackNode(id="c1", node_type="credential", label="db_creds",
                          artifact_ref="r4", properties={"artifact_id": "x4"}))
    g.add_node(AttackNode(id="s2", node_type="service", label="ssh:22",
                          artifact_ref="r5", properties={"artifact_id": "x5"}))
    g.add_node(AttackNode(id="p1", node_type="privilege", label="shell_access",
                          artifact_ref="r6", properties={"artifact_type": "shell_access"}))

    # Static edges
    g.add_edge(AttackEdge(source="ep", target="a1", edge_type="discovery"))
    g.add_edge(AttackEdge(source="a1", target="s1", edge_type="discovery"))
    g.add_edge(AttackEdge(source="s1", target="v1", edge_type="discovery"))

    # Before correlation
    enum_before = PathEnumerator(g)
    paths_before = enum_before.enumerate_paths()

    # Run correlator
    correlator = GraphCorrelator()
    new_edges = correlator.correlate(g)

    # After correlation — should have more edges
    assert len(new_edges) > 0

    # Re-enumerate paths with correlated edges
    enum_after = PathEnumerator(g)
    paths_after = enum_after.enumerate_paths()

    # Correlation should expand paths (vuln→credential, credential→service, etc.)
    assert len(paths_after) >= len(paths_before)


# ═══════════════════════════════════════════════════════════════════
# 10. ArtifactBus integration
# ═══════════════════════════════════════════════════════════════════


def test_artifact_bus_imports_correlator():
    import inspect
    from app.engine.artifact_bus import ArtifactBus
    source = inspect.getsource(ArtifactBus)
    assert "GraphCorrelator" in source


def test_artifact_bus_calls_correlate():
    import inspect
    from app.engine.artifact_bus import ArtifactBus
    source = inspect.getsource(ArtifactBus.process_completed_node)
    assert "correlate" in source


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
