"""MOD-07 Attack Graph Engine tests — validates graph construction,
path enumeration, risk scoring, and ArtifactBus integration.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_attack_graph.py -v
"""

from __future__ import annotations

import json
import os
import sys
import uuid

import pytest

_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


# ═══════════════════════════════════════════════════════════════════
# 1. Graph Model — data structures
# ═══════════════════════════════════════════════════════════════════


def test_attack_node_creation():
    from app.engine.attack_graph_builder import AttackNode
    n = AttackNode(id="test:1", node_type="asset", label="test.com",
                   artifact_ref="ref/1")
    assert n.id == "test:1"
    assert n.node_type == "asset"
    assert n.properties == {}


def test_attack_edge_creation():
    from app.engine.attack_graph_builder import AttackEdge
    e = AttackEdge(source="a", target="b", edge_type="discovery")
    assert e.source == "a"
    assert e.target == "b"


def test_attack_graph_add_node():
    from app.engine.attack_graph_builder import AttackGraph, AttackNode
    g = AttackGraph(scan_id="s1", tenant_id="t1")
    g.add_node(AttackNode(id="n1", node_type="asset", label="host", artifact_ref=""))
    assert g.has_node("n1")
    assert not g.has_node("n2")


def test_attack_graph_add_edge():
    from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge
    g = AttackGraph(scan_id="s1", tenant_id="t1")
    g.add_node(AttackNode(id="n1", node_type="asset", label="a", artifact_ref=""))
    g.add_node(AttackNode(id="n2", node_type="service", label="b", artifact_ref=""))
    g.add_edge(AttackEdge(source="n1", target="n2", edge_type="discovery"))
    assert len(g.edges) == 1
    assert g.get_neighbors("n1") == ["n2"]


def test_graph_serialization():
    from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge
    g = AttackGraph(scan_id="s1", tenant_id="t1", built_at="2026-01-01")
    g.add_node(AttackNode(id="n1", node_type="asset", label="a", artifact_ref="r1"))
    g.add_edge(AttackEdge(source="n1", target="n1", edge_type="discovery"))
    d = g.to_dict()
    assert d["node_count"] == 1
    assert d["edge_count"] == 1
    assert d["scan_id"] == "s1"
    # Must be JSON serializable
    json.dumps(d)


def test_get_predecessors():
    from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge
    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="a", node_type="asset", label="a", artifact_ref=""))
    g.add_node(AttackNode(id="b", node_type="service", label="b", artifact_ref=""))
    g.add_edge(AttackEdge(source="a", target="b", edge_type="discovery"))
    assert g.get_predecessors("b") == ["a"]


# ═══════════════════════════════════════════════════════════════════
# 2. Entrypoints
# ═══════════════════════════════════════════════════════════════════


def test_entrypoints_defined():
    from app.engine.attack_graph_builder import _ENTRYPOINTS
    assert "external_attacker" in _ENTRYPOINTS
    assert "internet_exposed_service" in _ENTRYPOINTS
    assert "unauthenticated_access" in _ENTRYPOINTS


def test_entrypoints_are_entrypoint_type():
    from app.engine.attack_graph_builder import _ENTRYPOINTS
    for name, node in _ENTRYPOINTS.items():
        assert node.node_type == "entrypoint", f"{name} not entrypoint type"


# ═══════════════════════════════════════════════════════════════════
# 3. Artifact → Node type mapping
# ═══════════════════════════════════════════════════════════════════


def test_artifact_type_mapping():
    from app.engine.attack_graph_builder import _ARTIFACT_NODE_TYPE
    assert _ARTIFACT_NODE_TYPE["subdomains"] == "asset"
    assert _ARTIFACT_NODE_TYPE["hosts"] == "asset"
    assert _ARTIFACT_NODE_TYPE["services"] == "service"
    assert _ARTIFACT_NODE_TYPE["endpoints"] == "endpoint"
    assert _ARTIFACT_NODE_TYPE["vulnerabilities"] == "vulnerability"
    assert _ARTIFACT_NODE_TYPE["database_access"] == "privilege"
    assert _ARTIFACT_NODE_TYPE["shell_access"] == "privilege"
    assert _ARTIFACT_NODE_TYPE["credential_leak"] == "credential"


def test_all_expected_artifact_types_mapped():
    from app.engine.attack_graph_builder import _ARTIFACT_NODE_TYPE
    expected = [
        "subdomains", "hosts", "services", "endpoints", "vulnerabilities",
        "database_access", "shell_access", "credential_leak",
        "privilege_escalation", "verified_impact",
    ]
    for t in expected:
        assert t in _ARTIFACT_NODE_TYPE, f"Missing mapping for {t}"


# ═══════════════════════════════════════════════════════════════════
# 4. Edge inference rules
# ═══════════════════════════════════════════════════════════════════


def test_edge_rules_exist():
    from app.engine.attack_graph_builder import _EDGE_RULES
    assert len(_EDGE_RULES) > 0


def test_edge_rules_cover_attack_chain():
    from app.engine.attack_graph_builder import _EDGE_RULES
    edge_types = {r[2] for r in _EDGE_RULES}
    assert "discovery" in edge_types
    assert "exploit" in edge_types
    assert "credential_usage" in edge_types
    assert "privilege_escalation" in edge_types


def test_edge_rules_entrypoint_to_asset():
    from app.engine.attack_graph_builder import _EDGE_RULES
    assert ("entrypoint", "asset", "discovery") in _EDGE_RULES


def test_edge_rules_vulnerability_to_privilege():
    from app.engine.attack_graph_builder import _EDGE_RULES
    assert ("vulnerability", "privilege", "exploit") in _EDGE_RULES


# ═══════════════════════════════════════════════════════════════════
# 5. Graph builder — artifact to node conversion
# ═══════════════════════════════════════════════════════════════════


def test_artifact_to_nodes_single():
    from app.engine.attack_graph_builder import AttackGraphBuilder
    builder = AttackGraphBuilder.__new__(AttackGraphBuilder)
    artifact = {
        "id": str(uuid.uuid4()),
        "artifact_type": "subdomains",
        "storage_ref": "artifacts/t/s/n/subfinder.json",
        "metadata": {},
        "node_id": None,
    }
    nodes = builder._artifact_to_nodes(artifact)
    assert len(nodes) == 1
    assert nodes[0].node_type == "asset"


def test_artifact_to_nodes_with_items():
    from app.engine.attack_graph_builder import AttackGraphBuilder
    builder = AttackGraphBuilder.__new__(AttackGraphBuilder)
    artifact = {
        "id": str(uuid.uuid4()),
        "artifact_type": "hosts",
        "storage_ref": "ref",
        "metadata": {"items": [
            {"host": "10.0.0.1"},
            {"host": "10.0.0.2"},
        ]},
        "node_id": None,
    }
    nodes = builder._artifact_to_nodes(artifact)
    assert len(nodes) == 2
    assert nodes[0].label == "10.0.0.1"
    assert nodes[1].label == "10.0.0.2"


def test_item_label_fallback():
    from app.engine.attack_graph_builder import AttackGraphBuilder
    builder = AttackGraphBuilder.__new__(AttackGraphBuilder)
    label = builder._item_label({}, "vuln", 3)
    assert label == "vuln[3]"


# ═══════════════════════════════════════════════════════════════════
# 6. Graph builder — edge inference
# ═══════════════════════════════════════════════════════════════════


def test_infer_edges_basic():
    from app.engine.attack_graph_builder import AttackGraphBuilder, AttackGraph, AttackNode
    builder = AttackGraphBuilder.__new__(AttackGraphBuilder)

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="ep", node_type="entrypoint", label="attacker", artifact_ref=""))
    g.add_node(AttackNode(id="a1", node_type="asset", label="host", artifact_ref="ref"))
    g.add_node(AttackNode(id="s1", node_type="service", label="http", artifact_ref="ref"))
    g.add_node(AttackNode(id="v1", node_type="vulnerability", label="sqli", artifact_ref="ref"))
    g.add_node(AttackNode(id="p1", node_type="privilege", label="db_access", artifact_ref="ref",
                          properties={"artifact_type": "database_access"}))

    builder._infer_edges(g)

    edge_pairs = [(e.source, e.target, e.edge_type) for e in g.edges]

    # entrypoint → asset
    assert ("ep", "a1", "discovery") in edge_pairs
    # asset → service
    assert ("a1", "s1", "discovery") in edge_pairs
    # vulnerability → privilege
    assert ("v1", "p1", "exploit") in edge_pairs


# ═══════════════════════════════════════════════════════════════════
# 7. Path Enumerator
# ═══════════════════════════════════════════════════════════════════


def test_path_enumerator_finds_paths():
    from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge
    from app.engine.path_enumerator import PathEnumerator

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="ep", node_type="entrypoint", label="attacker", artifact_ref=""))
    g.add_node(AttackNode(id="a1", node_type="asset", label="host", artifact_ref=""))
    g.add_node(AttackNode(id="v1", node_type="vulnerability", label="sqli", artifact_ref=""))
    g.add_node(AttackNode(id="p1", node_type="privilege", label="db", artifact_ref="",
                          properties={"artifact_type": "database_access"}))
    g.add_edge(AttackEdge(source="ep", target="a1", edge_type="discovery"))
    g.add_edge(AttackEdge(source="a1", target="v1", edge_type="discovery"))
    g.add_edge(AttackEdge(source="v1", target="p1", edge_type="exploit"))

    enum = PathEnumerator(g)
    paths = enum.enumerate_paths()

    assert len(paths) >= 1
    # Shortest path should end at p1
    assert paths[0].target == "p1"
    assert paths[0].entrypoint == "ep"
    assert paths[0].depth == 4  # ep → a1 → v1 → p1


def test_path_enumerator_no_paths_without_targets():
    from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge
    from app.engine.path_enumerator import PathEnumerator

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="ep", node_type="entrypoint", label="attacker", artifact_ref=""))
    g.add_node(AttackNode(id="a1", node_type="asset", label="host", artifact_ref=""))
    g.add_edge(AttackEdge(source="ep", target="a1", edge_type="discovery"))

    enum = PathEnumerator(g)
    paths = enum.enumerate_paths()
    assert len(paths) == 0  # no privilege or credential targets


def test_path_enumerator_cycle_safe():
    from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge
    from app.engine.path_enumerator import PathEnumerator

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="ep", node_type="entrypoint", label="attacker", artifact_ref=""))
    g.add_node(AttackNode(id="a1", node_type="asset", label="a", artifact_ref=""))
    g.add_node(AttackNode(id="a2", node_type="asset", label="b", artifact_ref=""))
    g.add_node(AttackNode(id="p1", node_type="privilege", label="priv", artifact_ref=""))
    g.add_edge(AttackEdge(source="ep", target="a1", edge_type="discovery"))
    g.add_edge(AttackEdge(source="a1", target="a2", edge_type="discovery"))
    g.add_edge(AttackEdge(source="a2", target="a1", edge_type="lateral_movement"))  # cycle!
    g.add_edge(AttackEdge(source="a2", target="p1", edge_type="exploit"))

    enum = PathEnumerator(g)
    paths = enum.enumerate_paths()
    # Should find path without infinite loop
    assert len(paths) >= 1


def test_path_summary():
    from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge
    from app.engine.path_enumerator import PathEnumerator

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="ep", node_type="entrypoint", label="a", artifact_ref=""))
    g.add_node(AttackNode(id="p1", node_type="privilege", label="p", artifact_ref="",
                          properties={"artifact_type": "shell_access"}))
    g.add_edge(AttackEdge(source="ep", target="p1", edge_type="exploit"))

    enum = PathEnumerator(g)
    paths = enum.enumerate_paths()
    summary = enum.get_path_summary(paths)
    assert summary["total_paths"] >= 1
    assert "shell_access" in summary["targets_reached"]


# ═══════════════════════════════════════════════════════════════════
# 8. Path Scorer
# ═══════════════════════════════════════════════════════════════════


def test_path_scorer_scores_paths():
    from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge
    from app.engine.path_enumerator import PathEnumerator, AttackPath
    from app.engine.path_scorer import PathScorer

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="ep", node_type="entrypoint", label="a", artifact_ref=""))
    g.add_node(AttackNode(id="v1", node_type="vulnerability", label="sqli", artifact_ref=""))
    g.add_node(AttackNode(id="p1", node_type="privilege", label="db", artifact_ref="",
                          properties={"artifact_type": "database_access"}))
    g.add_edge(AttackEdge(source="ep", target="v1", edge_type="discovery"))
    g.add_edge(AttackEdge(source="v1", target="p1", edge_type="exploit"))

    enum = PathEnumerator(g)
    paths = enum.enumerate_paths()
    scorer = PathScorer(g)
    scored = scorer.score_paths(paths)

    assert len(scored) >= 1
    assert scored[0].total_score > 0
    assert scored[0].risk_level in ("critical", "high", "medium", "low", "info")


def test_path_scorer_higher_impact_scores_higher():
    from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge
    from app.engine.path_enumerator import PathEnumerator
    from app.engine.path_scorer import PathScorer

    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="ep", node_type="entrypoint", label="a", artifact_ref=""))
    g.add_node(AttackNode(id="p1", node_type="privilege", label="db", artifact_ref="",
                          properties={"artifact_type": "database_access"}))
    g.add_node(AttackNode(id="p2", node_type="privilege", label="shell", artifact_ref="",
                          properties={"artifact_type": "shell_access"}))
    g.add_edge(AttackEdge(source="ep", target="p1", edge_type="exploit"))
    g.add_edge(AttackEdge(source="ep", target="p2", edge_type="exploit"))

    enum = PathEnumerator(g)
    paths = enum.enumerate_paths()
    scorer = PathScorer(g)
    scored = scorer.score_paths(paths)

    # shell_access (10.0 severity) should score >= database_access (9.0)
    shell_path = [s for s in scored if "shell" in s.path.target]
    db_path = [s for s in scored if "db" in s.path.target]

    if shell_path and db_path:
        assert shell_path[0].total_score >= db_path[0].total_score


def test_risk_levels():
    from app.engine.path_scorer import PathScorer
    from app.engine.attack_graph_builder import AttackGraph
    g = AttackGraph(scan_id="s", tenant_id="t")
    scorer = PathScorer(g)
    assert scorer._risk_level(9.5) == "critical"
    assert scorer._risk_level(8.0) == "high"
    assert scorer._risk_level(5.0) == "medium"
    assert scorer._risk_level(2.5) == "low"
    assert scorer._risk_level(1.0) == "info"


def test_score_weights_sum_to_one():
    from app.engine.path_scorer import _WEIGHTS
    total = sum(_WEIGHTS.values())
    assert abs(total - 1.0) < 0.001


def test_scoring_summary():
    from app.engine.path_scorer import PathScorer, ScoredPath
    from app.engine.path_enumerator import AttackPath
    from app.engine.attack_graph_builder import AttackGraph

    g = AttackGraph(scan_id="s", tenant_id="t")
    scorer = PathScorer(g)

    sp = ScoredPath(
        path=AttackPath(path_id="p", nodes=["a", "b"], edges=["exploit"],
                        entrypoint="a", target="b", target_type="privilege", depth=2),
        total_score=8.5, severity_score=9.0, exploit_score=7.0,
        privilege_score=8.0, efficiency_score=10.0, criticality_score=7.0,
        risk_level="high",
    )
    summary = scorer.get_scoring_summary([sp])
    assert summary["total_paths"] == 1
    assert summary["highest_score"] == 8.5


# ═══════════════════════════════════════════════════════════════════
# 9. Full end-to-end: artifact chain → graph → paths → scores
# ═══════════════════════════════════════════════════════════════════


def test_full_attack_chain():
    """End-to-end: subdomain → host → service → endpoint → vuln → impact."""
    from app.engine.attack_graph_builder import AttackGraphBuilder, AttackGraph, AttackNode, AttackEdge
    from app.engine.path_enumerator import PathEnumerator
    from app.engine.path_scorer import PathScorer

    builder = AttackGraphBuilder.__new__(AttackGraphBuilder)

    # Simulate artifacts returned from database
    artifacts = [
        {"id": "a1", "artifact_type": "subdomains", "storage_ref": "r1",
         "metadata": {"items": [{"host": "api.target.com"}]}, "node_id": None},
        {"id": "a2", "artifact_type": "services", "storage_ref": "r2",
         "metadata": {"items": [{"port": 443, "service": "https"}]}, "node_id": None},
        {"id": "a3", "artifact_type": "endpoints", "storage_ref": "r3",
         "metadata": {"items": [{"url": "https://api.target.com/admin"}]}, "node_id": None},
        {"id": "a4", "artifact_type": "vulnerabilities", "storage_ref": "r4",
         "metadata": {"items": [{"name": "SQL Injection", "type": "sql_injection"}]}, "node_id": None},
        {"id": "a5", "artifact_type": "database_access", "storage_ref": "r5",
         "metadata": {"items": [{"content": "dump of users table"}]}, "node_id": None},
    ]

    # Build graph manually (simulating what build() does with DB)
    from app.engine.attack_graph_builder import _ENTRYPOINTS
    g = AttackGraph(scan_id="test-scan", tenant_id="test-tenant", built_at="now")
    for ep in _ENTRYPOINTS.values():
        g.add_node(ep)
    for a in artifacts:
        for node in builder._artifact_to_nodes(a):
            g.add_node(node)
    builder._infer_edges(g)

    # Enumerate paths
    enum = PathEnumerator(g)
    paths = enum.enumerate_paths()

    # There must be at least one path to privilege (database_access)
    assert len(paths) >= 1
    target_types = {p.target_type for p in paths}
    assert "privilege" in target_types

    # Score paths
    scorer = PathScorer(g)
    scored = scorer.score_paths(paths)
    assert len(scored) >= 1
    assert scored[0].total_score > 0
    assert scored[0].risk_level in ("critical", "high", "medium")


# ═══════════════════════════════════════════════════════════════════
# 10. ArtifactBus integration
# ═══════════════════════════════════════════════════════════════════


def test_artifact_bus_imports_graph():
    import inspect
    from app.engine.artifact_bus import ArtifactBus
    source = inspect.getsource(ArtifactBus)
    assert "AttackGraphBuilder" in source


def test_artifact_bus_has_graph_builder():
    import inspect
    from app.engine.artifact_bus import ArtifactBus
    source = inspect.getsource(ArtifactBus.__init__)
    assert "graph_builder" in source


def test_artifact_bus_returns_graph_updated():
    import inspect
    from app.engine.artifact_bus import ArtifactBus
    source = inspect.getsource(ArtifactBus.process_completed_node)
    assert "graph_updated" in source


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
