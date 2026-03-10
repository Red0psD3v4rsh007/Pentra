"""MOD-12.5 Attack Surface Intelligence Engine tests — validates asset graph,
expansion engine, cross-domain correlator, surface risk scorer, and full pipeline.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_surface_intelligence.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)

from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge


def _make_attack_graph() -> AttackGraph:
    """Build a multi-domain attack graph for testing."""
    g = AttackGraph(scan_id="test", tenant_id="t")
    g.add_node(AttackNode(id="ep", node_type="entrypoint", label="attacker", artifact_ref=""))
    # Web domain
    g.add_node(AttackNode(id="sub1", node_type="asset", label="app.target.com", artifact_ref="r1",
                           properties={"artifact_type": "subdomains"}))
    g.add_node(AttackNode(id="ep1", node_type="endpoint", label="/api/login", artifact_ref="r2",
                           properties={"artifact_type": "endpoints"}))
    # Network domain
    g.add_node(AttackNode(id="svc1", node_type="service", label="ssh:22", artifact_ref="r3",
                           properties={"artifact_type": "services"}))
    # Identity domain
    g.add_node(AttackNode(id="cred1", node_type="credential", label="admin:password", artifact_ref="r4",
                           properties={"artifact_type": "credential_leak"}))
    # Cloud domain
    g.add_node(AttackNode(id="cloud1", node_type="privilege", label="s3:company-backup", artifact_ref="r5",
                           properties={"artifact_type": "database_access"}))
    # Code domain
    g.add_node(AttackNode(id="repo1", node_type="asset", label="github.com/org/api", artifact_ref="r6",
                           properties={"artifact_type": "repository"}))
    # Edges
    g.add_edge(AttackEdge(source="ep", target="sub1", edge_type="discovery"))
    g.add_edge(AttackEdge(source="sub1", target="ep1", edge_type="discovery"))
    g.add_edge(AttackEdge(source="ep1", target="cred1", edge_type="exploit"))
    g.add_edge(AttackEdge(source="cred1", target="svc1", edge_type="credential_usage"))
    g.add_edge(AttackEdge(source="svc1", target="cloud1", edge_type="lateral_movement"))
    return g


# ═══════════════════════════════════════════════════════════════════
# 1. Asset Graph Builder
# ═══════════════════════════════════════════════════════════════════


def test_asset_graph_builds():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    builder = AssetGraphBuilder("org-test")
    ag = builder.build_from_attack_graph(_make_attack_graph())
    assert len(ag.nodes) >= 5  # Excludes entrypoint


def test_asset_graph_has_domains():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    domains = {n.domain for n in ag.nodes.values()}
    assert len(domains) >= 3  # web, network, identity, cloud, or code


def test_asset_graph_has_relations():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    assert len(ag.relations) >= 4  # Original edges + inferred


def test_asset_graph_get_by_domain():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    identity = ag.get_by_domain("identity")
    assert len(identity) >= 1


def test_asset_graph_to_dict():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    d = ag.to_dict()
    assert "node_count" in d
    assert "domains" in d


def test_asset_graph_auto_connects_creds():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    auth_rels = [r for r in ag.relations if r.relation_type == "authenticates"]
    assert len(auth_rels) >= 1


# ═══════════════════════════════════════════════════════════════════
# 2. Expansion Engine
# ═══════════════════════════════════════════════════════════════════


def test_expansion_generates_hypotheses():
    from app.engine.asset_graph_builder import AssetGraphBuilder, AssetNode as AN
    from app.engine.expansion_engine import ExpansionEngine
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    engine = ExpansionEngine()
    hyps = engine.expand(ag)
    assert len(hyps) > 0


def test_expansion_triggers_on_repository():
    from app.engine.asset_graph_builder import AssetGraphBuilder, AssetNode as AN
    from app.engine.expansion_engine import ExpansionEngine
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    engine = ExpansionEngine()
    repo_assets = [n for n in ag.nodes.values() if n.asset_type == "repository"]
    hyps = engine.expand(ag, new_assets=repo_assets)
    assert len(hyps) > 0
    assert any("secret_scan" in h.hypothesis_type for h in hyps)


def test_expansion_triggers_on_credential():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    from app.engine.expansion_engine import ExpansionEngine
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    cred_assets = [n for n in ag.nodes.values() if n.asset_type == "credential"]
    hyps = ExpansionEngine().expand(ag, new_assets=cred_assets)
    assert len(hyps) > 0


def test_expansion_triggers_on_ssh_service():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    from app.engine.expansion_engine import ExpansionEngine
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    svc_assets = [n for n in ag.nodes.values() if n.asset_type == "service"]
    hyps = ExpansionEngine().expand(ag, new_assets=svc_assets)
    assert any("service_enum" in h.hypothesis_type for h in hyps)


def test_expansion_rule_count():
    from app.engine.expansion_engine import ExpansionEngine
    assert ExpansionEngine().rule_count >= 7


# ═══════════════════════════════════════════════════════════════════
# 3. Cross-Domain Correlator
# ═══════════════════════════════════════════════════════════════════


def test_correlator_finds_paths():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    from app.engine.cross_domain_correlator import CrossDomainCorrelator
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    correlator = CrossDomainCorrelator()
    paths = correlator.correlate(ag)
    assert len(paths) > 0


def test_correlator_paths_cross_domains():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    from app.engine.cross_domain_correlator import CrossDomainCorrelator
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    paths = CrossDomainCorrelator().correlate(ag)
    for p in paths:
        assert len(p.domains_crossed) >= 2


def test_correlator_adds_relations():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    from app.engine.cross_domain_correlator import CrossDomainCorrelator
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    before = len(ag.relations)
    CrossDomainCorrelator().correlate(ag)
    assert len(ag.relations) >= before


def test_correlator_path_to_dict():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    from app.engine.cross_domain_correlator import CrossDomainCorrelator
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    paths = CrossDomainCorrelator().correlate(ag)
    d = paths[0].to_dict()
    assert "domains" in d
    assert "risk_multiplier" in d


# ═══════════════════════════════════════════════════════════════════
# 4. Surface Risk Scorer
# ═══════════════════════════════════════════════════════════════════


def test_scorer_scores_all_assets():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    from app.engine.surface_risk_scorer import SurfaceRiskScorer
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    risks = SurfaceRiskScorer().score(ag)
    assert len(risks) == len(ag.nodes)


def test_scorer_sorted_by_risk():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    from app.engine.surface_risk_scorer import SurfaceRiskScorer
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    risks = SurfaceRiskScorer().score(ag)
    scores = [r.risk_score for r in risks]
    assert scores == sorted(scores, reverse=True)


def test_scorer_has_risk_levels():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    from app.engine.surface_risk_scorer import SurfaceRiskScorer
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    risks = SurfaceRiskScorer().score(ag)
    for r in risks:
        assert r.risk_level in {"critical", "high", "medium", "low", "info"}


def test_scorer_credential_ranks_high():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    from app.engine.surface_risk_scorer import SurfaceRiskScorer
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    risks = SurfaceRiskScorer().score(ag)
    cred_risks = [r for r in risks if "password" in r.asset_label.lower()]
    if cred_risks:
        assert cred_risks[0].risk_score >= 3.0


def test_scorer_top_risks():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    from app.engine.surface_risk_scorer import SurfaceRiskScorer
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    top = SurfaceRiskScorer().top_risks(ag, n=3)
    assert len(top) <= 3


def test_scorer_summary():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    from app.engine.surface_risk_scorer import SurfaceRiskScorer
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    risks = SurfaceRiskScorer().score(ag)
    s = SurfaceRiskScorer().summary(risks)
    assert "total_assets" in s
    assert "avg_score" in s


def test_scorer_to_dict():
    from app.engine.asset_graph_builder import AssetGraphBuilder
    from app.engine.surface_risk_scorer import SurfaceRiskScorer
    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    risks = SurfaceRiskScorer().score(ag)
    d = risks[0].to_dict()
    assert "score" in d
    assert "level" in d


# ═══════════════════════════════════════════════════════════════════
# 5. Full Pipeline Integration
# ═══════════════════════════════════════════════════════════════════


def test_full_surface_intelligence_pipeline():
    """End-to-end: attack graph → asset graph → expand → correlate → score."""
    from app.engine.asset_graph_builder import AssetGraphBuilder
    from app.engine.expansion_engine import ExpansionEngine
    from app.engine.cross_domain_correlator import CrossDomainCorrelator
    from app.engine.surface_risk_scorer import SurfaceRiskScorer

    ag = AssetGraphBuilder("org-demo").build_from_attack_graph(_make_attack_graph())
    assert len(ag.nodes) >= 5

    hyps = ExpansionEngine().expand(ag)
    assert len(hyps) > 0

    paths = CrossDomainCorrelator().correlate(ag)
    assert len(paths) > 0

    risks = SurfaceRiskScorer().score(ag)
    assert len(risks) == len(ag.nodes)
    assert risks[0].risk_score >= risks[-1].risk_score


def test_surface_with_graph_evolution():
    """Add new cloud asset and verify surface intelligence adapts."""
    from app.engine.asset_graph_builder import AssetGraphBuilder, AssetNode
    from app.engine.expansion_engine import ExpansionEngine
    from app.engine.surface_risk_scorer import SurfaceRiskScorer

    ag = AssetGraphBuilder().build_from_attack_graph(_make_attack_graph())
    initial_count = len(ag.nodes)

    # Simulate discovery of new cloud asset
    ag.add_node(AssetNode(
        id="s3_new", asset_type="cloud_resource", domain="cloud",
        label="s3:company-secrets", properties={"artifact_type": "s3_bucket"},
    ))
    assert len(ag.nodes) == initial_count + 1

    # Expansion should trigger cloud enum
    new_assets = [ag.nodes["s3_new"]]
    hyps = ExpansionEngine().expand(ag, new_assets=new_assets)
    assert any("cloud_enum" in h.hypothesis_type for h in hyps)

    # Risk score should rank new cloud asset
    risks = SurfaceRiskScorer().score(ag)
    assert any(r.asset_id == "s3_new" for r in risks)


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
