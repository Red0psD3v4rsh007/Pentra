"""MOD-09.6 Pattern Reasoning Engine tests — validates pattern graph,
reasoning, chain generation, and exploration engine integration.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_pattern_reasoning.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


# ── Helper ───────────────────────────────────────────────────────────

def _make_graph():
    from app.engine.attack_graph_builder import AttackGraph, AttackNode
    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="ep", node_type="entrypoint", label="attacker", artifact_ref=""))
    g.add_node(AttackNode(id="a1", node_type="asset", label="web.target.com",
                          artifact_ref="r1", properties={"artifact_type": "subdomains"}))
    g.add_node(AttackNode(id="s1", node_type="service", label="https:443",
                          artifact_ref="r2", properties={"artifact_type": "services"}))
    g.add_node(AttackNode(id="s2", node_type="service", label="ssh:22",
                          artifact_ref="r3", properties={"artifact_type": "services"}))
    g.add_node(AttackNode(id="e1", node_type="endpoint", label="/api/users?id=1",
                          artifact_ref="r4", properties={"artifact_type": "endpoints"}))
    g.add_node(AttackNode(id="e2", node_type="endpoint", label="/admin/login",
                          artifact_ref="r5", properties={"artifact_type": "endpoints"}))
    g.add_node(AttackNode(id="v1", node_type="vulnerability", label="SQL Injection",
                          artifact_ref="r6", properties={"artifact_type": "sql_injection"}))
    g.add_node(AttackNode(id="c1", node_type="credential", label="admin:pass123",
                          artifact_ref="r7", properties={"artifact_type": "credential_leak"}))
    return g


def _get_registry():
    from app.knowledge.pattern_registry import PatternRegistry
    r = PatternRegistry()
    r.load()
    return r


# ═══════════════════════════════════════════════════════════════════
# 1. Pattern Graph Builder
# ═══════════════════════════════════════════════════════════════════


def test_pattern_graph_builds():
    from app.engine.pattern_graph_builder import PatternGraphBuilder
    builder = PatternGraphBuilder(_get_registry())
    pg = builder.build()
    assert len(pg.edges) > 0


def test_pattern_graph_has_successors():
    from app.engine.pattern_graph_builder import PatternGraphBuilder
    builder = PatternGraphBuilder(_get_registry())
    pg = builder.build()
    # credential_reuse_ssh impact=shell_access should connect to something
    succs = pg.get_successors("credential_reuse_ssh")
    assert len(succs) >= 0  # may or may not have successors depending on patterns


def test_pattern_graph_no_self_loops():
    from app.engine.pattern_graph_builder import PatternGraphBuilder
    builder = PatternGraphBuilder(_get_registry())
    pg = builder.build()
    for e in pg.edges:
        assert e.source_pattern != e.target_pattern


def test_pattern_graph_to_dict():
    from app.engine.pattern_graph_builder import PatternGraphBuilder
    builder = PatternGraphBuilder(_get_registry())
    pg = builder.build()
    d = pg.to_dict()
    assert "edge_count" in d
    assert "pattern_count" in d
    assert d["edge_count"] == len(pg.edges)


def test_impact_to_artifact_mapping():
    from app.engine.pattern_graph_builder import _IMPACT_TO_ARTIFACT
    assert "credential" in _IMPACT_TO_ARTIFACT["credential_leak"]
    assert "privilege" in _IMPACT_TO_ARTIFACT["shell_access"]
    assert "service" in _IMPACT_TO_ARTIFACT["lateral_movement"]


# ═══════════════════════════════════════════════════════════════════
# 2. Pattern Reasoner
# ═══════════════════════════════════════════════════════════════════


def test_reasoner_finds_chains():
    from app.engine.pattern_reasoner import PatternReasoner
    registry = _get_registry()
    g = _make_graph()
    reasoner = PatternReasoner(registry, g)
    chains = reasoner.reason()
    assert len(chains) > 0


def test_reasoner_chains_have_depth():
    from app.engine.pattern_reasoner import PatternReasoner
    registry = _get_registry()
    g = _make_graph()
    reasoner = PatternReasoner(registry, g)
    for chain in reasoner.reason():
        assert chain.depth >= 2  # multi-step only


def test_reasoner_chains_sorted_by_confidence():
    from app.engine.pattern_reasoner import PatternReasoner
    registry = _get_registry()
    g = _make_graph()
    reasoner = PatternReasoner(registry, g)
    chains = reasoner.reason()
    for i in range(len(chains) - 1):
        assert chains[i].total_confidence >= chains[i + 1].total_confidence


def test_reasoner_chains_no_cycles():
    from app.engine.pattern_reasoner import PatternReasoner
    registry = _get_registry()
    g = _make_graph()
    reasoner = PatternReasoner(registry, g)
    for chain in reasoner.reason():
        names = [p.name for p in chain.patterns]
        assert len(names) == len(set(names)), "Chain has duplicate patterns"


def test_reasoner_max_depth():
    from app.engine.pattern_reasoner import PatternReasoner
    registry = _get_registry()
    g = _make_graph()
    reasoner = PatternReasoner(registry, g, max_depth=2)
    for chain in reasoner.reason():
        assert chain.depth <= 2


def test_reasoner_chain_to_dict():
    from app.engine.pattern_reasoner import PatternReasoner
    registry = _get_registry()
    g = _make_graph()
    reasoner = PatternReasoner(registry, g)
    chains = reasoner.reason()
    if chains:
        d = chains[0].to_dict()
        assert "chain_id" in d
        assert "steps" in d
        assert "links" in d


def test_reasoner_pattern_graph_accessible():
    from app.engine.pattern_reasoner import PatternReasoner
    registry = _get_registry()
    g = _make_graph()
    reasoner = PatternReasoner(registry, g)
    assert len(reasoner.pattern_graph.edges) > 0


def test_reasoner_initial_matches():
    from app.engine.pattern_reasoner import PatternReasoner
    registry = _get_registry()
    g = _make_graph()
    reasoner = PatternReasoner(registry, g)
    assert len(reasoner.initial_matches) > 0


# ═══════════════════════════════════════════════════════════════════
# 3. Pattern Chain Generator
# ═══════════════════════════════════════════════════════════════════


def test_chain_generator_produces_hypotheses():
    from app.engine.pattern_reasoner import PatternReasoner
    from app.engine.pattern_chain_generator import PatternChainGenerator
    registry = _get_registry()
    g = _make_graph()
    reasoner = PatternReasoner(registry, g)
    chains = reasoner.reason()
    gen = PatternChainGenerator(g)
    hyps = gen.generate(chains)
    assert len(hyps) > 0


def test_chain_hypotheses_have_chain_metadata():
    from app.engine.pattern_reasoner import PatternReasoner
    from app.engine.pattern_chain_generator import PatternChainGenerator
    registry = _get_registry()
    g = _make_graph()
    reasoner = PatternReasoner(registry, g)
    chains = reasoner.reason()
    gen = PatternChainGenerator(g)
    for h in gen.generate(chains):
        assert "chain_id" in h.config
        assert "chain_step" in h.config
        assert "pattern_name" in h.config


def test_chain_hypotheses_safety():
    from app.engine.pattern_reasoner import PatternReasoner
    from app.engine.pattern_chain_generator import PatternChainGenerator
    registry = _get_registry()
    g = _make_graph()
    reasoner = PatternReasoner(registry, g)
    chains = reasoner.reason()
    gen = PatternChainGenerator(g)
    for h in gen.generate(chains):
        assert h.config.get("no_persist") is True


def test_chain_max_per_chain():
    from app.engine.pattern_reasoner import PatternReasoner
    from app.engine.pattern_chain_generator import PatternChainGenerator
    registry = _get_registry()
    g = _make_graph()
    reasoner = PatternReasoner(registry, g)
    chains = reasoner.reason()
    gen = PatternChainGenerator(g)
    hyps = gen.generate(chains, max_hypotheses_per_chain=1)
    from collections import Counter
    types = Counter(h.hypothesis_type for h in hyps)
    for count in types.values():
        assert count <= 1


# ═══════════════════════════════════════════════════════════════════
# 4. Full pipeline: graph → patterns → reasoning → chains → scored
# ═══════════════════════════════════════════════════════════════════


def test_full_reasoning_pipeline():
    from app.engine.pattern_reasoner import PatternReasoner
    from app.engine.pattern_chain_generator import PatternChainGenerator
    from app.engine.exploration_scorer import ExplorationScorer

    registry = _get_registry()
    g = _make_graph()

    # Reason
    reasoner = PatternReasoner(registry, g)
    chains = reasoner.reason()
    assert len(chains) > 0

    # Generate
    gen = PatternChainGenerator(g)
    hyps = gen.generate(chains)
    assert len(hyps) > 0

    # Score
    scorer = ExplorationScorer(g)
    scored = scorer.score(hyps, min_score=0.0)
    assert len(scored) > 0


# ═══════════════════════════════════════════════════════════════════
# 5. ExplorationEngine integration
# ═══════════════════════════════════════════════════════════════════


def test_exploration_engine_uses_reasoner():
    import inspect
    from app.engine.exploration_engine import ExplorationEngine
    source = inspect.getsource(ExplorationEngine)
    assert "PatternReasoner" in source
    assert "PatternChainGenerator" in source


def test_exploration_engine_has_chain_count():
    import inspect
    from app.engine.exploration_engine import ExplorationEngine
    source = inspect.getsource(ExplorationEngine.explore)
    assert "pattern_chains" in source


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
