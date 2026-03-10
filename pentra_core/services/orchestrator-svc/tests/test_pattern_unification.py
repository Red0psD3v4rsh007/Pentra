"""MOD-09.7 Pattern Unification tests — verifies full knowledge-driven
exploration, rule removal, pattern coverage, and schema expansion.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_pattern_unification.py -v
"""

from __future__ import annotations

import inspect
import os
import sys
from collections import Counter

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
# 1. Rule Removal Verification
# ═══════════════════════════════════════════════════════════════════


def test_exploration_engine_no_hypothesis_generator():
    """ExplorationEngine must NOT use HypothesisGenerator."""
    from app.engine.exploration_engine import ExplorationEngine
    source = inspect.getsource(ExplorationEngine.__init__)
    assert "HypothesisGenerator" not in source


def test_exploration_engine_no_rule_based_generation():
    """ExplorationEngine.explore must NOT call _hyp_gen.generate()."""
    from app.engine.exploration_engine import ExplorationEngine
    source = inspect.getsource(ExplorationEngine.explore)
    assert "_hyp_gen" not in source


def test_exploration_engine_only_pattern_sources():
    """ExplorationEngine must only use PatternMatcher + PatternReasoner."""
    from app.engine.exploration_engine import ExplorationEngine
    source = inspect.getsource(ExplorationEngine)
    assert "PatternMatcher" in source
    assert "PatternReasoner" in source
    assert "HypothesisGenerator(graph)" not in source


# ═══════════════════════════════════════════════════════════════════
# 2. Pattern Schema v2
# ═══════════════════════════════════════════════════════════════════


def test_patterns_have_confidence_score():
    registry = _get_registry()
    for p in registry.patterns:
        assert 0.0 <= p.confidence_score <= 1.0


def test_patterns_have_priority():
    registry = _get_registry()
    valid = {"critical", "high", "medium", "low"}
    for p in registry.patterns:
        assert p.priority in valid, f"{p.name} has invalid priority: {p.priority}"


def test_patterns_have_generated_artifacts():
    registry = _get_registry()
    for p in registry.patterns:
        assert isinstance(p.generated_artifacts, list)


def test_pattern_to_dict_includes_new_fields():
    registry = _get_registry()
    d = registry.patterns[0].to_dict()
    assert "confidence_score" in d
    assert "priority" in d
    assert "generated_artifacts" in d


def test_pattern_count_expanded():
    registry = _get_registry()
    assert registry.count >= 22  # 11 web + 7 network + 4 cloud


# ═══════════════════════════════════════════════════════════════════
# 3. Pattern Coverage Validation (all 6 rule behaviors)
# ═══════════════════════════════════════════════════════════════════


def _get_all_pattern_hypotheses():
    from app.engine.pattern_matcher import PatternMatcher
    from app.engine.pattern_executor import PatternExecutor
    registry = _get_registry()
    g = _make_graph()
    matcher = PatternMatcher(registry, g)
    matches = matcher.match_all()
    executor = PatternExecutor(g)
    return executor.generate_hypotheses(matches)


def test_coverage_endpoint_fuzz():
    """endpoint_fuzz rule behavior: endpoint → fuzz parameters."""
    hyps = _get_all_pattern_hypotheses()
    endpoint_hyps = [h for h in hyps if "endpoint" in h.target_label.lower() or
                     h.config.get("target_type") == "endpoint"]
    assert len(endpoint_hyps) > 0


def test_coverage_credential_reuse():
    """credential_reuse rule behavior: credential → reuse attempt."""
    registry = _get_registry()
    cred_patterns = [p for p in registry.patterns if "credential_reuse" in p.name]
    assert len(cred_patterns) >= 3  # ssh, ftp, rdp, generic


def test_coverage_route_guessing():
    """route_guess rule behavior: endpoint → hidden route discovery."""
    registry = _get_registry()
    route_patterns = [p for p in registry.patterns
                      if "route" in p.name or "admin_endpoint" in p.name]
    assert len(route_patterns) >= 2


def test_coverage_parameter_mutation():
    """param_mutation rule behavior: vulnerability → parameter mutation."""
    registry = _get_registry()
    p = registry.get_pattern("param_mutation_testing")
    assert p is not None
    assert p.preconditions[0].artifact_type == "vulnerability"


def test_coverage_service_pivoting():
    """service_pivot rule behavior: service → lateral movement."""
    registry = _get_registry()
    p = registry.get_pattern("service_pivot")
    assert p is not None
    assert "lateral_movement" in p.impact


def test_coverage_api_discovery():
    """api_discovery rule behavior: asset → API endpoint enumeration."""
    registry = _get_registry()
    p = registry.get_pattern("api_discovery")
    assert p is not None
    assert p.preconditions[0].artifact_type == "asset"


# ═══════════════════════════════════════════════════════════════════
# 4. Pattern Reasoning Still Works
# ═══════════════════════════════════════════════════════════════════


def test_reasoning_produces_chains():
    from app.engine.pattern_reasoner import PatternReasoner
    registry = _get_registry()
    g = _make_graph()
    reasoner = PatternReasoner(registry, g)
    chains = reasoner.reason()
    assert len(chains) > 0


def test_chains_produce_hypotheses():
    from app.engine.pattern_reasoner import PatternReasoner
    from app.engine.pattern_chain_generator import PatternChainGenerator
    registry = _get_registry()
    g = _make_graph()
    reasoner = PatternReasoner(registry, g)
    chains = reasoner.reason()
    gen = PatternChainGenerator(g)
    hyps = gen.generate(chains)
    assert len(hyps) > 0


# ═══════════════════════════════════════════════════════════════════
# 5. Full Knowledge Pipeline
# ═══════════════════════════════════════════════════════════════════


def test_full_knowledge_pipeline_no_rules():
    """End-to-end: patterns → hypotheses → scored — with zero rules."""
    from app.engine.pattern_matcher import PatternMatcher
    from app.engine.pattern_executor import PatternExecutor
    from app.engine.pattern_reasoner import PatternReasoner
    from app.engine.pattern_chain_generator import PatternChainGenerator
    from app.engine.exploration_scorer import ExplorationScorer

    registry = _get_registry()
    g = _make_graph()

    # Pattern-based
    matcher = PatternMatcher(registry, g)
    matches = matcher.match_all()
    executor = PatternExecutor(g)
    hypotheses = executor.generate_hypotheses(matches)

    # Chain-based
    reasoner = PatternReasoner(registry, g)
    chains = reasoner.reason()
    chain_gen = PatternChainGenerator(g)
    hypotheses.extend(chain_gen.generate(chains))

    assert len(hypotheses) > 0

    # All hypotheses must have pattern metadata or chain metadata
    for h in hypotheses:
        has_pattern = h.config.get("pattern_name") is not None
        has_chain = h.config.get("chain_id") is not None
        assert has_pattern or has_chain, f"Hypothesis {h.hypothesis_id} has no pattern or chain metadata"

    # Score
    scorer = ExplorationScorer(g)
    scored = scorer.score(hypotheses, min_score=0.0)
    assert len(scored) > 0


def test_no_rule_hypotheses_in_full_pipeline():
    """Verify no hypothesis has 'rule' key in config (old format)."""
    from app.engine.pattern_matcher import PatternMatcher
    from app.engine.pattern_executor import PatternExecutor

    registry = _get_registry()
    g = _make_graph()
    matcher = PatternMatcher(registry, g)
    matches = matcher.match_all()
    executor = PatternExecutor(g)
    for h in executor.generate_hypotheses(matches):
        assert "rule" not in h.config, f"Hypothesis {h.hypothesis_id} still uses rule-based config"


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
