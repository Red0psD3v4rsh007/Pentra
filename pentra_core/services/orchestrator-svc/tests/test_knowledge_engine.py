"""MOD-09.5 Offensive Knowledge Engine tests — validates pattern registry,
matcher, executor, and exploration engine integration.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_knowledge_engine.py -v
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


# ── Helper ───────────────────────────────────────────────────────────

def _make_graph():
    from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge
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
    registry = PatternRegistry()
    registry.load()
    return registry


# ═══════════════════════════════════════════════════════════════════
# 1. Pattern Registry
# ═══════════════════════════════════════════════════════════════════


def test_registry_loads_patterns():
    registry = _get_registry()
    assert registry.count >= 15  # 7 web + 6 network + 4 cloud ≈ 17


def test_registry_has_domains():
    registry = _get_registry()
    domains = registry.get_domains()
    assert "web" in domains
    assert "network" in domains
    assert "cloud" in domains


def test_registry_get_by_domain():
    registry = _get_registry()
    web = registry.get_patterns(domain="web")
    assert len(web) >= 5
    for p in web:
        assert p.domain == "web"


def test_registry_get_by_name():
    registry = _get_registry()
    p = registry.get_pattern("credential_reuse_ssh")
    assert p is not None
    assert p.domain == "network"


def test_registry_pattern_has_preconditions():
    registry = _get_registry()
    for p in registry.patterns:
        assert len(p.preconditions) >= 1


def test_registry_pattern_has_actions():
    registry = _get_registry()
    for p in registry.patterns:
        assert len(p.actions) >= 1
        for a in p.actions:
            assert a.tool
            assert a.worker_family


def test_registry_pattern_has_impact():
    registry = _get_registry()
    for p in registry.patterns:
        assert len(p.impact) >= 1


def test_registry_no_duplicate_names():
    registry = _get_registry()
    names = [p.name for p in registry.patterns]
    assert len(names) == len(set(names))


def test_pattern_to_dict():
    registry = _get_registry()
    p = registry.patterns[0]
    d = p.to_dict()
    assert "name" in d
    assert "preconditions" in d
    assert "actions" in d
    assert "impact" in d


# ═══════════════════════════════════════════════════════════════════
# 2. Pattern Matcher
# ═══════════════════════════════════════════════════════════════════


def test_matcher_finds_matches():
    from app.engine.pattern_matcher import PatternMatcher
    registry = _get_registry()
    g = _make_graph()
    matcher = PatternMatcher(registry, g)
    matches = matcher.match_all()
    assert len(matches) > 0


def test_matcher_confidence_range():
    from app.engine.pattern_matcher import PatternMatcher
    registry = _get_registry()
    g = _make_graph()
    matcher = PatternMatcher(registry, g)
    for m in matcher.match_all():
        assert 0.5 <= m.confidence <= 1.0


def test_matcher_sorted_by_confidence():
    from app.engine.pattern_matcher import PatternMatcher
    registry = _get_registry()
    g = _make_graph()
    matcher = PatternMatcher(registry, g)
    matches = matcher.match_all()
    for i in range(len(matches) - 1):
        assert matches[i].confidence >= matches[i + 1].confidence


def test_matcher_credential_ssh_pattern():
    """Graph with credential + SSH service should match credential_reuse_ssh."""
    from app.engine.pattern_matcher import PatternMatcher
    registry = _get_registry()
    g = _make_graph()
    matcher = PatternMatcher(registry, g)
    matches = matcher.match_all()
    matched_names = [m.pattern.name for m in matches]
    assert "credential_reuse_ssh" in matched_names


def test_matcher_idor_pattern():
    """Endpoint with id= should match idor_enumeration."""
    from app.engine.pattern_matcher import PatternMatcher
    registry = _get_registry()
    g = _make_graph()
    matcher = PatternMatcher(registry, g)
    matches = matcher.match_all()
    matched_names = [m.pattern.name for m in matches]
    assert "idor_enumeration" in matched_names


def test_matcher_auth_bypass_pattern():
    """Endpoint with /admin/login should match auth_bypass."""
    from app.engine.pattern_matcher import PatternMatcher
    registry = _get_registry()
    g = _make_graph()
    matcher = PatternMatcher(registry, g)
    matches = matcher.match_all()
    matched_names = [m.pattern.name for m in matches]
    assert "auth_bypass" in matched_names


def test_matcher_domain_filter():
    from app.engine.pattern_matcher import PatternMatcher
    registry = _get_registry()
    g = _make_graph()
    matcher = PatternMatcher(registry, g)
    web_matches = matcher.match_all(domain="web")
    for m in web_matches:
        assert m.pattern.domain == "web"


def test_matcher_match_to_dict():
    from app.engine.pattern_matcher import PatternMatcher
    registry = _get_registry()
    g = _make_graph()
    matcher = PatternMatcher(registry, g)
    matches = matcher.match_all()
    d = matches[0].to_dict()
    assert "pattern_name" in d
    assert "confidence" in d


# ═══════════════════════════════════════════════════════════════════
# 3. Pattern Executor
# ═══════════════════════════════════════════════════════════════════


def test_executor_generates_hypotheses():
    from app.engine.pattern_matcher import PatternMatcher
    from app.engine.pattern_executor import PatternExecutor
    registry = _get_registry()
    g = _make_graph()
    matcher = PatternMatcher(registry, g)
    matches = matcher.match_all()
    executor = PatternExecutor(g)
    hypotheses = executor.generate_hypotheses(matches)
    assert len(hypotheses) > 0


def test_executor_hypotheses_have_pattern_metadata():
    from app.engine.pattern_matcher import PatternMatcher
    from app.engine.pattern_executor import PatternExecutor
    registry = _get_registry()
    g = _make_graph()
    matcher = PatternMatcher(registry, g)
    matches = matcher.match_all()
    executor = PatternExecutor(g)
    for h in executor.generate_hypotheses(matches):
        assert h.config.get("pattern_name")
        assert h.config.get("pattern_domain")
        assert "confidence" in h.config


def test_executor_hypotheses_have_safety():
    from app.engine.pattern_matcher import PatternMatcher
    from app.engine.pattern_executor import PatternExecutor
    registry = _get_registry()
    g = _make_graph()
    matcher = PatternMatcher(registry, g)
    matches = matcher.match_all()
    executor = PatternExecutor(g)
    for h in executor.generate_hypotheses(matches):
        assert h.config.get("no_persist") is True


def test_executor_max_per_pattern():
    from app.engine.pattern_matcher import PatternMatcher
    from app.engine.pattern_executor import PatternExecutor
    registry = _get_registry()
    g = _make_graph()
    matcher = PatternMatcher(registry, g)
    matches = matcher.match_all()
    executor = PatternExecutor(g)
    limited = executor.generate_hypotheses(matches, max_per_pattern=1)
    # Each pattern should produce at most 1 hypothesis
    from collections import Counter
    types = Counter(h.hypothesis_type for h in limited)
    for count in types.values():
        assert count <= 1


def test_executor_hypothesis_ids_unique():
    from app.engine.pattern_matcher import PatternMatcher
    from app.engine.pattern_executor import PatternExecutor
    registry = _get_registry()
    g = _make_graph()
    matcher = PatternMatcher(registry, g)
    matches = matcher.match_all()
    executor = PatternExecutor(g)
    ids = [h.hypothesis_id for h in executor.generate_hypotheses(matches)]
    assert len(ids) == len(set(ids))


# ═══════════════════════════════════════════════════════════════════
# 4. Full pipeline: registry → matcher → executor → scorer
# ═══════════════════════════════════════════════════════════════════


def test_full_knowledge_pipeline():
    """End-to-end: patterns → matches → hypotheses → scored."""
    from app.engine.pattern_matcher import PatternMatcher
    from app.engine.pattern_executor import PatternExecutor
    from app.engine.exploration_scorer import ExplorationScorer

    registry = _get_registry()
    g = _make_graph()

    # Match
    matcher = PatternMatcher(registry, g)
    matches = matcher.match_all()
    assert len(matches) > 0

    # Execute
    executor = PatternExecutor(g)
    hypotheses = executor.generate_hypotheses(matches)
    assert len(hypotheses) > 0

    # Score
    scorer = ExplorationScorer(g)
    scored = scorer.score(hypotheses, min_score=3.0)
    assert len(scored) > 0


# ═══════════════════════════════════════════════════════════════════
# 5. ExplorationEngine integration
# ═══════════════════════════════════════════════════════════════════


def test_exploration_engine_uses_patterns():
    import inspect
    from app.engine.exploration_engine import ExplorationEngine
    source = inspect.getsource(ExplorationEngine)
    assert "PatternRegistry" in source
    assert "PatternMatcher" in source
    assert "PatternExecutor" in source


def test_exploration_engine_has_pattern_matches():
    import inspect
    from app.engine.exploration_engine import ExplorationEngine
    source = inspect.getsource(ExplorationEngine.explore)
    assert "pattern_matches" in source


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
