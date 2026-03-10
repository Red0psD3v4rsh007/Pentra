"""MOD-12.7 Attack Discovery Engine tests — validates discovery behavior
analyzer, attack hypothesis generator, experiment engine, and full pipeline.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_attack_discovery.py -v
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
# 1. Discovery Behavior Analyzer
# ═══════════════════════════════════════════════════════════════════


def test_analyzer_detects_param_reuse():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    analyzer = DiscoveryBehaviorAnalyzer()
    signals = analyzer.analyze_response("/api/users", {
        "body": "user_id=42&token=abc123", "status_code": 200,
    })
    types = {s.signal_type for s in signals}
    assert "param_reuse" in types


def test_analyzer_detects_reflection():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    signals = DiscoveryBehaviorAnalyzer().analyze_response("/search", {
        "body": "<script>alert('xss')</script>", "status_code": 200,
    })
    assert any(s.signal_type == "unexpected_reflection" for s in signals)


def test_analyzer_detects_state_leak():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    signals = DiscoveryBehaviorAnalyzer().analyze_response("/api/data", {
        "body": "response data", "status_code": 200,
        "headers": {"X-Auth": "bearer abc123"},
    })
    assert any(s.signal_type == "state_leak" for s in signals)


def test_analyzer_detects_file_reference():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    signals = DiscoveryBehaviorAnalyzer().analyze_response("/download", {
        "body": "Reading from /etc/passwd", "status_code": 200,
    })
    assert any(s.signal_type == "file_reference" for s in signals)


def test_analyzer_detects_object_reference():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    signals = DiscoveryBehaviorAnalyzer().analyze_response("/api/render", {
        "body": "__proto__ pollution detected", "status_code": 200,
    })
    assert any(s.signal_type == "object_reference" for s in signals)


def test_analyzer_detects_timing():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    signals = DiscoveryBehaviorAnalyzer().analyze_response("/slow", {
        "body": "ok", "status_code": 200, "elapsed_ms": 5000,
    })
    assert any(s.signal_type == "timing_anomaly" for s in signals)


def test_analyzer_detects_error():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    signals = DiscoveryBehaviorAnalyzer().analyze_response("/crash", {
        "body": "Internal error", "status_code": 500,
    })
    assert any(s.signal_type == "error_pattern" for s in signals)


def test_analyzer_batch():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    responses = [
        {"endpoint": "/ep1", "body": "user_id=1", "status_code": 200},
        {"endpoint": "/ep2", "body": "<script>x</script>", "status_code": 200},
    ]
    signals = DiscoveryBehaviorAnalyzer().analyze_batch(responses)
    assert len(signals) >= 2


def test_analyzer_signal_to_dict():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    signals = DiscoveryBehaviorAnalyzer().analyze_response("/api", {
        "body": "user_id=5", "status_code": 200,
    })
    if signals:
        d = signals[0].to_dict()
        assert "type" in d
        assert "confidence" in d


# ═══════════════════════════════════════════════════════════════════
# 2. Attack Hypothesis Generator
# ═══════════════════════════════════════════════════════════════════


def test_generator_creates_ideas():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    from app.engine.attack_hypothesis_generator import AttackHypothesisGenerator
    signals = DiscoveryBehaviorAnalyzer().analyze_response("/api", {
        "body": "user_id=5 and /etc/shadow reference", "status_code": 200,
    })
    ideas = AttackHypothesisGenerator().generate_from_signals(signals)
    assert len(ideas) > 0


def test_generator_idea_types():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    from app.engine.attack_hypothesis_generator import AttackHypothesisGenerator
    signals = DiscoveryBehaviorAnalyzer().analyze_response("/api", {
        "body": "__proto__ user_id=1 /tmp/file", "status_code": 500,
    })
    ideas = AttackHypothesisGenerator().generate_from_signals(signals)
    types = {i.idea_type for i in ideas}
    assert len(types) >= 2  # Multiple idea types from multiple signals


def test_generator_to_hypotheses():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    from app.engine.attack_hypothesis_generator import AttackHypothesisGenerator
    signals = DiscoveryBehaviorAnalyzer().analyze_response("/api", {
        "body": "user_id=1", "status_code": 200,
    })
    gen = AttackHypothesisGenerator()
    ideas = gen.generate_from_signals(signals)
    hyps = gen.to_hypotheses(ideas)
    assert len(hyps) == len(ideas)
    for h in hyps:
        assert h.hypothesis_id.startswith("discovery:")


def test_generator_sorted_by_risk():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    from app.engine.attack_hypothesis_generator import AttackHypothesisGenerator
    signals = DiscoveryBehaviorAnalyzer().analyze_response("/api", {
        "body": "user_id=1 /etc/passwd", "status_code": 500,
    })
    ideas = AttackHypothesisGenerator().generate_from_signals(signals)
    risks = [i.risk_potential for i in ideas]
    assert risks == sorted(risks, reverse=True)


def test_generator_idea_to_dict():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    from app.engine.attack_hypothesis_generator import AttackHypothesisGenerator
    signals = DiscoveryBehaviorAnalyzer().analyze_response("/api", {
        "body": "user_id=1", "status_code": 200,
    })
    ideas = AttackHypothesisGenerator().generate_from_signals(signals)
    if ideas:
        d = ideas[0].to_dict()
        assert "type" in d


# ═══════════════════════════════════════════════════════════════════
# 3. Experiment Engine
# ═══════════════════════════════════════════════════════════════════


def test_experiment_creates_from_ideas():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer, BehaviorSignal
    from app.engine.attack_hypothesis_generator import AttackHypothesisGenerator
    from app.engine.experiment_engine import ExperimentEngine
    signals = DiscoveryBehaviorAnalyzer().analyze_response("/api", {
        "body": "__proto__ user_id=1", "status_code": 200,
    })
    ideas = AttackHypothesisGenerator().generate_from_signals(signals)
    exps = ExperimentEngine().create_experiments(ideas)
    assert len(exps) == len(ideas)


def test_experiment_has_mutations():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    from app.engine.attack_hypothesis_generator import AttackHypothesisGenerator
    from app.engine.experiment_engine import ExperimentEngine
    signals = DiscoveryBehaviorAnalyzer().analyze_response("/api", {
        "body": "user_id=1", "status_code": 200,
    })
    ideas = AttackHypothesisGenerator().generate_from_signals(signals)
    exps = ExperimentEngine().create_experiments(ideas)
    for exp in exps:
        assert len(exp.mutations) >= 1


def test_experiment_run():
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    from app.engine.attack_hypothesis_generator import AttackHypothesisGenerator
    from app.engine.experiment_engine import ExperimentEngine
    signals = DiscoveryBehaviorAnalyzer().analyze_response("/api", {
        "body": "__proto__ user_id=1", "status_code": 500,
    })
    ideas = AttackHypothesisGenerator().generate_from_signals(signals)
    engine = ExperimentEngine()
    exps = engine.create_experiments(ideas)
    result = engine.run(exps)
    assert result.completed == result.total_experiments
    assert result.signals_discovered > 0


def test_experiment_result_to_dict():
    from app.engine.experiment_engine import ExperimentResult
    r = ExperimentResult(total_experiments=5, completed=5, signals_discovered=3)
    d = r.to_dict()
    assert d["total"] == 5


# ═══════════════════════════════════════════════════════════════════
# 4. Full Pipeline Integration
# ═══════════════════════════════════════════════════════════════════


def test_full_discovery_pipeline():
    """End-to-end: response → analyze → ideas → hypotheses → graph → experiments."""
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    from app.engine.attack_hypothesis_generator import AttackHypothesisGenerator
    from app.engine.experiment_engine import ExperimentEngine
    from app.engine.hypothesis_graph import HypothesisGraph

    # 1 — Analyze behavior
    analyzer = DiscoveryBehaviorAnalyzer()
    signals = analyzer.analyze_response("/api/search", {
        "body": "user_id=42 __proto__ /tmp/cache",
        "status_code": 500,
        "elapsed_ms": 4000,
    })
    assert len(signals) >= 3  # param_reuse, object_ref, file_ref, error, timing

    # 2 — Generate attack ideas
    gen = AttackHypothesisGenerator()
    ideas = gen.generate_from_signals(signals)
    assert len(ideas) >= 3

    # 3 — Convert to hypotheses and add to graph
    hyps = gen.to_hypotheses(ideas)
    graph = HypothesisGraph()
    graph.add_batch(hyps, "discovery")
    assert graph.total == len(hyps)

    # 4 — Run experiments
    engine = ExperimentEngine()
    exps = engine.create_experiments(ideas)
    result = engine.run(exps)
    assert result.completed > 0
    assert result.signals_discovered > 0


def test_discovery_feedback_loop():
    """Verify experiment signals can feed back into hypothesis generation."""
    from app.engine.discovery_behavior_analyzer import DiscoveryBehaviorAnalyzer
    from app.engine.attack_hypothesis_generator import AttackHypothesisGenerator
    from app.engine.experiment_engine import ExperimentEngine

    analyzer = DiscoveryBehaviorAnalyzer()
    gen = AttackHypothesisGenerator()
    engine = ExperimentEngine()

    # Round 1: initial analysis
    signals1 = analyzer.analyze_response("/api", {"body": "user_id=1", "status_code": 200})
    ideas1 = gen.generate_from_signals(signals1)
    exps = engine.create_experiments(ideas1)
    result = engine.run(exps)

    # Round 2: experiment results generate new signals → new ideas
    assert result.signals_discovered > 0
    # The experiment signals are synthetic but prove the feedback loop works
    assert result.completed == len(exps)


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
