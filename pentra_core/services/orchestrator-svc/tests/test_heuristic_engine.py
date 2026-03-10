"""MOD-11 Heuristic Vulnerability Engine tests — validates heuristic matcher,
test generator, result analyzer, and exploration integration.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_heuristic_engine.py -v
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
    g.add_node(AttackNode(id="e1", node_type="endpoint", label="/api/users?id=1",
                          artifact_ref="r4", properties={"artifact_type": "endpoints"}))
    g.add_node(AttackNode(id="e2", node_type="endpoint", label="/admin/login",
                          artifact_ref="r5", properties={"artifact_type": "endpoints"}))
    g.add_node(AttackNode(id="e3", node_type="endpoint", label="/api/v2/checkout?price=100",
                          artifact_ref="r8", properties={"artifact_type": "endpoints"}))
    g.add_node(AttackNode(id="v1", node_type="vulnerability", label="SQL Injection",
                          artifact_ref="r6", properties={"artifact_type": "sql_injection"}))
    return g


# ═══════════════════════════════════════════════════════════════════
# 1. Heuristic Definitions Loading
# ═══════════════════════════════════════════════════════════════════


def test_heuristics_load():
    from app.engine.heuristic_matcher import HeuristicMatcher
    g = _make_graph()
    matcher = HeuristicMatcher(g)
    assert len(matcher.heuristics) >= 12


def test_heuristics_have_categories():
    from app.engine.heuristic_matcher import HeuristicMatcher
    g = _make_graph()
    matcher = HeuristicMatcher(g)
    categories = {h.category for h in matcher.heuristics}
    assert "access_control" in categories
    assert "authentication" in categories
    assert "information_disclosure" in categories


def test_heuristics_have_confidence():
    from app.engine.heuristic_matcher import HeuristicMatcher
    g = _make_graph()
    matcher = HeuristicMatcher(g)
    for h in matcher.heuristics:
        assert 0.0 <= h.confidence <= 1.0


# ═══════════════════════════════════════════════════════════════════
# 2. Heuristic Matcher
# ═══════════════════════════════════════════════════════════════════


def test_matcher_finds_idor_on_numeric_param():
    from app.engine.heuristic_matcher import HeuristicMatcher
    g = _make_graph()
    matcher = HeuristicMatcher(g)
    matches = matcher.match_all()
    idor = [m for m in matches if m.heuristic.name == "idor_numeric_param"]
    assert len(idor) > 0
    assert idor[0].matched_node_id == "e1"


def test_matcher_finds_auth_bypass_on_login():
    from app.engine.heuristic_matcher import HeuristicMatcher
    g = _make_graph()
    matcher = HeuristicMatcher(g)
    matches = matcher.match_all()
    auth = [m for m in matches if m.heuristic.name == "auth_bypass_token"]
    assert len(auth) > 0


def test_matcher_finds_default_creds_on_login():
    from app.engine.heuristic_matcher import HeuristicMatcher
    g = _make_graph()
    matcher = HeuristicMatcher(g)
    matches = matcher.match_all()
    creds = [m for m in matches if m.heuristic.name == "default_credentials"]
    assert len(creds) > 0


def test_matcher_finds_price_manipulation():
    from app.engine.heuristic_matcher import HeuristicMatcher
    g = _make_graph()
    matcher = HeuristicMatcher(g)
    matches = matcher.match_all()
    price = [m for m in matches if m.heuristic.name == "price_manipulation"]
    assert len(price) > 0


def test_matcher_finds_debug_endpoint_on_service():
    from app.engine.heuristic_matcher import HeuristicMatcher
    g = _make_graph()
    matcher = HeuristicMatcher(g)
    matches = matcher.match_all()
    debug = [m for m in matches if m.heuristic.name == "debug_endpoint_exposure"]
    assert len(debug) > 0


def test_matcher_sorted_by_confidence():
    from app.engine.heuristic_matcher import HeuristicMatcher
    g = _make_graph()
    matcher = HeuristicMatcher(g)
    matches = matcher.match_all()
    confidences = [m.heuristic.confidence for m in matches]
    assert confidences == sorted(confidences, reverse=True)


def test_matcher_skips_entrypoint():
    from app.engine.heuristic_matcher import HeuristicMatcher
    g = _make_graph()
    matcher = HeuristicMatcher(g)
    matches = matcher.match_all()
    ep_matches = [m for m in matches if m.matched_node_id == "ep"]
    assert len(ep_matches) == 0


def test_match_to_dict():
    from app.engine.heuristic_matcher import HeuristicMatcher
    g = _make_graph()
    matcher = HeuristicMatcher(g)
    matches = matcher.match_all()
    d = matches[0].to_dict()
    assert "heuristic_name" in d
    assert "matched_indicators" in d


# ═══════════════════════════════════════════════════════════════════
# 3. Heuristic Test Generator
# ═══════════════════════════════════════════════════════════════════


def test_generator_produces_hypotheses():
    from app.engine.heuristic_matcher import HeuristicMatcher
    from app.engine.heuristic_test_generator import HeuristicTestGenerator
    g = _make_graph()
    matcher = HeuristicMatcher(g)
    matches = matcher.match_all()
    gen = HeuristicTestGenerator(g)
    hyps = gen.generate(matches)
    assert len(hyps) > 0


def test_generator_hypotheses_have_heuristic_metadata():
    from app.engine.heuristic_matcher import HeuristicMatcher
    from app.engine.heuristic_test_generator import HeuristicTestGenerator
    g = _make_graph()
    matcher = HeuristicMatcher(g)
    matches = matcher.match_all()
    gen = HeuristicTestGenerator(g)
    for h in gen.generate(matches):
        assert h.config.get("heuristic_name")
        assert h.config.get("vulnerability_class")
        assert h.config.get("no_persist") is True


def test_generator_respects_max_per_heuristic():
    from app.engine.heuristic_matcher import HeuristicMatcher
    from app.engine.heuristic_test_generator import HeuristicTestGenerator
    g = _make_graph()
    matcher = HeuristicMatcher(g)
    matches = matcher.match_all()
    gen = HeuristicTestGenerator(g)
    hyps = gen.generate(matches, max_per_heuristic=1)
    h_names = [h.config.get("heuristic_name") for h in hyps]
    from collections import Counter
    counts = Counter(h_names)
    for count in counts.values():
        assert count <= 1


def test_generator_ids_are_prefixed():
    from app.engine.heuristic_matcher import HeuristicMatcher
    from app.engine.heuristic_test_generator import HeuristicTestGenerator
    g = _make_graph()
    matcher = HeuristicMatcher(g)
    gen = HeuristicTestGenerator(g)
    for h in gen.generate(matcher.match_all()):
        assert h.hypothesis_id.startswith("heur:")


# ═══════════════════════════════════════════════════════════════════
# 4. Heuristic Result Analyzer
# ═══════════════════════════════════════════════════════════════════


def test_analyzer_confirms_stack_trace():
    from app.engine.heuristic_analyzer import HeuristicAnalyzer
    analyzer = HeuristicAnalyzer()
    result = analyzer.analyze(
        test_output={
            "status_code": 500,
            "response_body": "Traceback (most recent call at line 42): ValueError at /var/app/main.py email=test",
        },
        heuristic_config={
            "heuristic_name": "verbose_error_disclosure",
            "vulnerability_class": "verbose_errors",
            "test_type": "error_trigger_test",
            "confidence": 0.6,
            "impact": ["information_disclosure"],
        },
    )
    assert result.verdict in ("confirmed", "likely")
    assert len(result.evidence) > 0


def test_analyzer_likely_on_single_evidence():
    from app.engine.heuristic_analyzer import HeuristicAnalyzer
    analyzer = HeuristicAnalyzer()
    result = analyzer.analyze(
        test_output={
            "status_code": 200,
            "response_body": "debug mode enabled",
        },
        heuristic_config={
            "heuristic_name": "debug_endpoint_exposure",
            "vulnerability_class": "debug_exposure",
            "test_type": "debug_endpoint_scan",
            "confidence": 0.5,
            "impact": ["information_disclosure"],
        },
    )
    assert result.verdict == "likely"


def test_analyzer_negative_on_clean_response():
    from app.engine.heuristic_analyzer import HeuristicAnalyzer
    analyzer = HeuristicAnalyzer()
    result = analyzer.analyze(
        test_output={
            "status_code": 403,
            "response_body": "Forbidden",
        },
        heuristic_config={
            "heuristic_name": "auth_bypass_token",
            "vulnerability_class": "auth_bypass",
            "test_type": "token_replay_test",
            "confidence": 0.6,
            "impact": ["authentication_bypass"],
        },
    )
    assert result.verdict == "negative"


def test_analyzer_confirms_auth_bypass():
    from app.engine.heuristic_analyzer import HeuristicAnalyzer
    analyzer = HeuristicAnalyzer()
    result = analyzer.analyze(
        test_output={
            "status_code": 200,
            "response_body": "Welcome admin, email: admin@test.com, password hash: abc123",
            "indicators": ["authenticated_without_credentials"],
        },
        heuristic_config={
            "heuristic_name": "default_credentials",
            "vulnerability_class": "weak_credentials",
            "test_type": "default_credential_test",
            "confidence": 0.6,
            "impact": ["authentication_bypass"],
        },
    )
    assert result.verdict == "confirmed"
    assert result.confidence > 0.6


def test_analyzer_result_to_dict():
    from app.engine.heuristic_analyzer import HeuristicAnalyzer
    analyzer = HeuristicAnalyzer()
    result = analyzer.analyze(
        test_output={"status_code": 200, "response_body": "ok"},
        heuristic_config={"heuristic_name": "test", "vulnerability_class": "test",
                          "test_type": "t", "confidence": 0.5, "impact": []},
    )
    d = result.to_dict()
    assert "verdict" in d
    assert "vulnerability_class" in d


# ═══════════════════════════════════════════════════════════════════
# 5. ExplorationEngine Integration
# ═══════════════════════════════════════════════════════════════════


def test_exploration_engine_has_heuristic_components():
    import inspect
    from app.engine.exploration_engine import ExplorationEngine
    source = inspect.getsource(ExplorationEngine)
    assert "HeuristicMatcher" in source
    assert "HeuristicTestGenerator" in source


def test_exploration_engine_has_heuristic_step():
    import inspect
    from app.engine.exploration_engine import ExplorationEngine
    source = inspect.getsource(ExplorationEngine.explore)
    assert "heuristic_matches" in source
    assert "heuristic_hypotheses" in source


# ═══════════════════════════════════════════════════════════════════
# 6. Full Heuristic Pipeline
# ═══════════════════════════════════════════════════════════════════


def test_full_heuristic_pipeline():
    """End-to-end: graph → match heuristics → generate tests → score."""
    from app.engine.heuristic_matcher import HeuristicMatcher
    from app.engine.heuristic_test_generator import HeuristicTestGenerator
    from app.engine.exploration_scorer import ExplorationScorer

    g = _make_graph()
    matcher = HeuristicMatcher(g)
    matches = matcher.match_all()
    gen = HeuristicTestGenerator(g)
    hyps = gen.generate(matches)
    assert len(hyps) > 0

    scorer = ExplorationScorer(g)
    scored = scorer.score(hyps, min_score=0.0)
    assert len(scored) > 0


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
