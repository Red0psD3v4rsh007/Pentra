"""MOD-09 Exploration Engine tests — validates hypotheses, scoring, budget,
memory, exploration engine, and ArtifactBus integration.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_exploration_engine.py -v
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
    from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge
    g = AttackGraph(scan_id="s", tenant_id="t")
    g.add_node(AttackNode(id="ep", node_type="entrypoint", label="attacker", artifact_ref=""))
    g.add_node(AttackNode(id="a1", node_type="asset", label="web.target.com",
                          artifact_ref="r1", properties={"artifact_type": "subdomains", "artifact_id": "x1"}))
    g.add_node(AttackNode(id="s1", node_type="service", label="https:443",
                          artifact_ref="r2", properties={"artifact_type": "services", "artifact_id": "x2"}))
    g.add_node(AttackNode(id="e1", node_type="endpoint", label="/api/users?id=1",
                          artifact_ref="r3", properties={"artifact_type": "endpoints", "artifact_id": "x3"}))
    g.add_node(AttackNode(id="v1", node_type="vulnerability", label="SQL Injection",
                          artifact_ref="r4", properties={"artifact_type": "sql_injection", "artifact_id": "x4"}))
    g.add_node(AttackNode(id="c1", node_type="credential", label="admin:pass",
                          artifact_ref="r5", properties={"artifact_type": "credential_leak", "artifact_id": "x5"}))
    return g


# ═══════════════════════════════════════════════════════════════════
# 1. Hypothesis Generator
# ═══════════════════════════════════════════════════════════════════


def test_hypothesis_rules_exist():
    from app.engine.hypothesis_generator import HYPOTHESIS_RULES
    assert len(HYPOTHESIS_RULES) >= 6


def test_hypothesis_rule_types():
    from app.engine.hypothesis_generator import HYPOTHESIS_RULES
    types = {r.hypothesis_type for r in HYPOTHESIS_RULES}
    assert "endpoint_fuzz" in types
    assert "route_guess" in types
    assert "credential_reuse" in types
    assert "service_pivot" in types
    assert "api_discovery" in types
    assert "param_mutation" in types


def test_generate_hypotheses():
    from app.engine.hypothesis_generator import HypothesisGenerator
    g = _make_graph()
    gen = HypothesisGenerator(g)
    hypotheses = gen.generate()
    assert len(hypotheses) > 0


def test_hypotheses_skip_entrypoints():
    from app.engine.hypothesis_generator import HypothesisGenerator
    g = _make_graph()
    gen = HypothesisGenerator(g)
    hypotheses = gen.generate()
    for h in hypotheses:
        assert h.target_node_id != "ep"


def test_hypotheses_have_tools():
    from app.engine.hypothesis_generator import HypothesisGenerator
    g = _make_graph()
    gen = HypothesisGenerator(g)
    for h in gen.generate():
        assert h.tool
        assert h.worker_family


def test_hypotheses_have_safety_config():
    from app.engine.hypothesis_generator import HypothesisGenerator
    g = _make_graph()
    gen = HypothesisGenerator(g)
    for h in gen.generate():
        assert h.config.get("no_persist") is True


def test_max_per_rule_limit():
    from app.engine.hypothesis_generator import HypothesisGenerator
    g = _make_graph()
    gen = HypothesisGenerator(g)
    hypotheses = gen.generate(max_per_rule=1)
    types = [h.hypothesis_type for h in hypotheses]
    # Each type should appear at most once per rule
    from collections import Counter
    counts = Counter(types)
    for htype, c in counts.items():
        assert c <= 6  # max 1 per rule, 6 rules


# ═══════════════════════════════════════════════════════════════════
# 2. Exploration Scorer
# ═══════════════════════════════════════════════════════════════════


def test_scorer_weights_sum_to_one():
    from app.engine.exploration_scorer import _SCORE_WEIGHTS
    assert abs(sum(_SCORE_WEIGHTS.values()) - 1.0) < 0.001


def test_scorer_scores_hypotheses():
    from app.engine.hypothesis_generator import HypothesisGenerator
    from app.engine.exploration_scorer import ExplorationScorer
    g = _make_graph()
    gen = HypothesisGenerator(g)
    hypotheses = gen.generate()
    scorer = ExplorationScorer(g)
    scored = scorer.score(hypotheses, min_score=0.0)
    assert len(scored) > 0
    assert all(s.total_score >= 0 for s in scored)


def test_scorer_filters_low_scores():
    from app.engine.hypothesis_generator import HypothesisGenerator
    from app.engine.exploration_scorer import ExplorationScorer
    g = _make_graph()
    gen = HypothesisGenerator(g)
    hypotheses = gen.generate()
    scorer = ExplorationScorer(g)
    all_scored = scorer.score(hypotheses, min_score=0.0)
    filtered = scorer.score(hypotheses, min_score=99.0)
    assert len(filtered) == 0
    assert len(all_scored) > 0


def test_scorer_priority_levels():
    from app.engine.exploration_scorer import ExplorationScorer
    from app.engine.attack_graph_builder import AttackGraph
    g = AttackGraph(scan_id="s", tenant_id="t")
    scorer = ExplorationScorer(g)
    assert scorer._priority_level(9.0) == "critical"
    assert scorer._priority_level(7.0) == "high"
    assert scorer._priority_level(5.0) == "medium"
    assert scorer._priority_level(2.0) == "low"


def test_scorer_sorted_descending():
    from app.engine.hypothesis_generator import HypothesisGenerator
    from app.engine.exploration_scorer import ExplorationScorer
    g = _make_graph()
    gen = HypothesisGenerator(g)
    hypotheses = gen.generate()
    scorer = ExplorationScorer(g)
    scored = scorer.score(hypotheses, min_score=0.0)
    for i in range(len(scored) - 1):
        assert scored[i].total_score >= scored[i + 1].total_score


# ═══════════════════════════════════════════════════════════════════
# 3. Exploration Budget
# ═══════════════════════════════════════════════════════════════════


def test_budget_defaults():
    from app.engine.exploration_budget import ExplorationBudget
    b = ExplorationBudget()
    assert b.config.max_exploration_tasks == 5000
    assert b.config.max_parallel_exploration == 20
    assert b.config.max_exploration_depth == 6


def test_budget_can_create():
    from app.engine.exploration_budget import ExplorationBudget
    b = ExplorationBudget()
    assert b.can_create(count=1)
    assert b.can_create(count=20)
    assert not b.can_create(count=21)  # exceeds parallel limit


def test_budget_consume_and_remaining():
    from app.engine.exploration_budget import ExplorationBudget, BudgetConfig
    b = ExplorationBudget(BudgetConfig(max_exploration_tasks=10, max_parallel_exploration=5))
    assert b.remaining == 10
    b.consume(count=3)
    assert b.remaining == 7
    assert b.tasks_created == 3
    assert b.active_tasks == 3


def test_budget_release():
    from app.engine.exploration_budget import ExplorationBudget, BudgetConfig
    b = ExplorationBudget(BudgetConfig(max_exploration_tasks=10, max_parallel_exploration=5))
    b.consume(count=3)
    b.release(count=2)
    assert b.active_tasks == 1
    assert b.tasks_created == 3  # total stays


def test_budget_exhaustion():
    from app.engine.exploration_budget import ExplorationBudget, BudgetConfig
    b = ExplorationBudget(BudgetConfig(max_exploration_tasks=3))
    b.consume(count=3)
    assert not b.can_create(count=1)
    assert b.remaining == 0


def test_budget_depth_limit():
    from app.engine.exploration_budget import ExplorationBudget
    b = ExplorationBudget()
    assert b.can_create(count=1, depth=6)
    assert not b.can_create(count=1, depth=7)


def test_budget_get_allowed():
    from app.engine.exploration_budget import ExplorationBudget, BudgetConfig
    b = ExplorationBudget(BudgetConfig(max_exploration_tasks=5, max_parallel_exploration=3))
    assert b.get_allowed_count(10) == 3  # capped by parallel
    b.consume(count=2)
    assert b.get_allowed_count(10) == 1  # 3-2=1 parallel room


def test_budget_status():
    from app.engine.exploration_budget import ExplorationBudget
    b = ExplorationBudget()
    s = b.get_status()
    assert "remaining" in s
    assert "max_tasks" in s


# ═══════════════════════════════════════════════════════════════════
# 4. Exploration Memory
# ═══════════════════════════════════════════════════════════════════


def test_memory_empty():
    from app.engine.exploration_memory import ExplorationMemory
    m = ExplorationMemory()
    assert m.total_explored == 0
    assert not m.has_explored(hypothesis_type="x", target_node_id="n", tool="t")


def test_memory_record_and_check():
    from app.engine.exploration_memory import ExplorationMemory
    m = ExplorationMemory()
    m.record(hypothesis_type="endpoint_fuzz", target_node_id="e1", tool="custom_poc")
    assert m.has_explored(hypothesis_type="endpoint_fuzz", target_node_id="e1", tool="custom_poc")
    assert not m.has_explored(hypothesis_type="endpoint_fuzz", target_node_id="e2", tool="custom_poc")
    assert m.total_explored == 1


def test_memory_different_tool_not_explored():
    from app.engine.exploration_memory import ExplorationMemory
    m = ExplorationMemory()
    m.record(hypothesis_type="endpoint_fuzz", target_node_id="e1", tool="custom_poc")
    assert not m.has_explored(hypothesis_type="endpoint_fuzz", target_node_id="e1", tool="sqlmap")


def test_memory_mark_result():
    from app.engine.exploration_memory import ExplorationMemory
    m = ExplorationMemory()
    m.record(hypothesis_type="x", target_node_id="n", tool="t")
    m.mark_result(hypothesis_type="x", target_node_id="n", tool="t", result="success")
    s = m.get_status()
    assert s["results"]["success"] == 1


def test_memory_status():
    from app.engine.exploration_memory import ExplorationMemory
    m = ExplorationMemory()
    m.record(hypothesis_type="a", target_node_id="1", tool="t")
    m.record(hypothesis_type="b", target_node_id="2", tool="t")
    s = m.get_status()
    assert s["total_explored"] == 2


# ═══════════════════════════════════════════════════════════════════
# 5. Full end-to-end (without DB)
# ═══════════════════════════════════════════════════════════════════


def test_full_exploration_pipeline():
    """End-to-end: graph → hypotheses → scored → budget checked."""
    from app.engine.hypothesis_generator import HypothesisGenerator
    from app.engine.exploration_scorer import ExplorationScorer
    from app.engine.exploration_budget import ExplorationBudget, BudgetConfig
    from app.engine.exploration_memory import ExplorationMemory

    g = _make_graph()

    # Generate
    gen = HypothesisGenerator(g)
    hypotheses = gen.generate()
    assert len(hypotheses) > 0

    # Memory filter
    memory = ExplorationMemory()
    novel = [h for h in hypotheses if not memory.has_explored(
        hypothesis_type=h.hypothesis_type,
        target_node_id=h.target_node_id,
        tool=h.tool,
    )]
    assert len(novel) == len(hypotheses)  # first time, all novel

    # Score
    scorer = ExplorationScorer(g)
    scored = scorer.score(novel, min_score=3.0)
    assert len(scored) > 0

    # Budget
    budget = ExplorationBudget(BudgetConfig(max_exploration_tasks=100))
    allowed = budget.get_allowed_count(len(scored))
    assert allowed > 0

    selected = scored[:allowed]

    # Record
    for sh in selected:
        memory.record(
            hypothesis_type=sh.hypothesis.hypothesis_type,
            target_node_id=sh.hypothesis.target_node_id,
            tool=sh.hypothesis.tool,
        )
    budget.consume(count=len(selected))

    assert memory.total_explored == len(selected)
    assert budget.tasks_created == len(selected)

    # Second pass — should be all remembered
    novel2 = [h for h in hypotheses if not memory.has_explored(
        hypothesis_type=h.hypothesis_type,
        target_node_id=h.target_node_id,
        tool=h.tool,
    )]
    assert len(novel2) < len(hypotheses)


# ═══════════════════════════════════════════════════════════════════
# 6. ArtifactBus integration
# ═══════════════════════════════════════════════════════════════════


def test_artifact_bus_imports_exploration():
    import inspect
    from app.engine.artifact_bus import ArtifactBus
    source = inspect.getsource(ArtifactBus)
    assert "ExplorationEngine" in source


def test_artifact_bus_returns_exploration_count():
    import inspect
    from app.engine.artifact_bus import ArtifactBus
    source = inspect.getsource(ArtifactBus.process_completed_node)
    assert "exploration_nodes_created" in source


def test_exploration_engine_includes_workflow_mutation_stage():
    import inspect
    from app.engine.exploration_engine import ExplorationEngine

    source = inspect.getsource(ExplorationEngine.explore)
    assert "InteractionMapper" in source
    assert "WorkflowMutator" in source
    assert "workflow_hypotheses" in source


def test_stateful_profile_filter_keeps_only_bounded_workflow_mutations():
    from app.engine.exploration_engine import _filter_exploration_hypotheses
    from app.engine.hypothesis_generator import Hypothesis

    hypotheses = [
        Hypothesis(
            hypothesis_id="recon:dns",
            hypothesis_type="recon_subdomain_analysis",
            target_node_id="a1",
            target_label="api.target.local",
            description="dns brute-force",
            tool="dns_bruteforce",
            worker_family="recon",
            config={"no_persist": True},
        ),
        Hypothesis(
            hypothesis_id="generic:web_fingerprint",
            hypothesis_type="recon_web_service_fingerprint",
            target_node_id="s1",
            target_label="https://target.local",
            description="generic custom poc",
            tool="custom_poc",
            worker_family="web",
            config={"no_persist": True},
        ),
        Hypothesis(
            hypothesis_id="wf:payment:skip",
            hypothesis_type="workflow_skip_step",
            target_node_id="e1",
            target_label="Skip payment flow",
            description="Skip payment flow",
            tool="custom_poc",
            worker_family="exploit",
            config={
                "workflow_mutation": "skip_step",
                "workflow_type": "payment",
                "target_url": "http://127.0.0.1:8088/portal/checkout/confirm",
                "no_persist": True,
            },
        ),
        Hypothesis(
            hypothesis_id="wf:auth:cross",
            hypothesis_type="workflow_cross_session",
            target_node_id="e2",
            target_label="Cross auth flow",
            description="Cross auth flow",
            tool="custom_poc",
            worker_family="exploit",
            config={
                "workflow_mutation": "cross_session",
                "workflow_type": "auth",
                "target_url": "http://127.0.0.1:8088/login",
                "no_persist": True,
            },
        ),
    ]

    filtered = _filter_exploration_hypotheses(
        hypotheses,
        scan_config={
            "profile_id": "external_web_api_v1",
            "stateful_testing": {"enabled": True, "max_replays": 4},
        },
    )

    assert len(filtered) == 2
    assert all(h.tool == "custom_poc" for h in filtered)
    assert all(h.config.get("workflow_mutation") for h in filtered)


def test_stateful_profile_filter_prioritizes_diverse_workflows_and_caps_replays():
    from app.engine.exploration_engine import _select_stateful_workflow_hypotheses
    from app.engine.hypothesis_generator import Hypothesis

    hypotheses = [
        Hypothesis(
            hypothesis_id="wf:payment:skip",
            hypothesis_type="workflow_skip_step",
            target_node_id="p1",
            target_label="payment skip",
            description="payment skip",
            tool="custom_poc",
            worker_family="exploit",
            config={
                "workflow_mutation": "skip_step",
                "workflow_type": "payment",
                "target_url": "http://127.0.0.1:8088/portal/checkout/confirm",
            },
        ),
        Hypothesis(
            hypothesis_id="wf:payment:swap",
            hypothesis_type="workflow_swap_order",
            target_node_id="p2",
            target_label="payment swap",
            description="payment swap",
            tool="custom_poc",
            worker_family="exploit",
            config={
                "workflow_mutation": "swap_order",
                "workflow_type": "payment",
                "target_url": "http://127.0.0.1:8088/portal/orders/review",
            },
        ),
        Hypothesis(
            hypothesis_id="wf:admin:cross",
            hypothesis_type="workflow_cross_session",
            target_node_id="a1",
            target_label="admin cross",
            description="admin cross",
            tool="custom_poc",
            worker_family="exploit",
            config={
                "workflow_mutation": "cross_session",
                "workflow_type": "admin",
                "target_url": "http://127.0.0.1:8088/portal/admin",
            },
        ),
        Hypothesis(
            hypothesis_id="wf:user:modify",
            hypothesis_type="workflow_modify_id",
            target_node_id="u1",
            target_label="user modify",
            description="user modify",
            tool="custom_poc",
            worker_family="exploit",
            config={
                "workflow_mutation": "modify_id",
                "workflow_type": "user_mgmt",
                "target_url": "http://127.0.0.1:8088/portal/account",
            },
        ),
        Hypothesis(
            hypothesis_id="wf:auth:repeat",
            hypothesis_type="workflow_repeat_step",
            target_node_id="l1",
            target_label="auth repeat",
            description="auth repeat",
            tool="custom_poc",
            worker_family="exploit",
            config={
                "workflow_mutation": "repeat_step",
                "workflow_type": "auth",
                "target_url": "http://127.0.0.1:8088/login",
            },
        ),
    ]

    selected = _select_stateful_workflow_hypotheses(hypotheses, max_hypotheses=3)

    assert len(selected) == 3
    assert selected[0].config["workflow_type"] == "payment"
    assert {item.config["workflow_type"] for item in selected} == {"payment", "admin", "user_mgmt"}


def test_exploration_engine_reuses_memory_per_scan():
    from app.engine.exploration_engine import ExplorationEngine

    graph = _make_graph()
    engine_a = ExplorationEngine(session=None, graph=graph)
    engine_b = ExplorationEngine(session=None, graph=graph)

    memory_a = engine_a._shared_memory("scan-1")
    memory_b = engine_b._shared_memory("scan-1")
    memory_c = engine_b._shared_memory("scan-2")

    memory_a.record(
        hypothesis_type="workflow_skip_step",
        target_node_id="e1",
        tool="custom_poc",
    )

    assert memory_a is memory_b
    assert memory_a is not memory_c
    assert memory_b.has_explored(
        hypothesis_type="workflow_skip_step",
        target_node_id="e1",
        tool="custom_poc",
    )


def test_orchestrator_resolves_exploration_nodes():
    import inspect
    from app.services.orchestrator_service import OrchestratorService
    source = inspect.getsource(OrchestratorService.handle_job_completed)
    assert "exploration_nodes_created" in source


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
