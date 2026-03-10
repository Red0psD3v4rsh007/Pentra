"""MOD-12 Offensive Reasoning Engine tests — validates attack planner,
action selector, budget manager, feedback controller, and full pipeline.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_reasoning_engine.py -v
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


def _make_graph() -> AttackGraph:
    """Build a realistic attack graph for testing."""
    g = AttackGraph(scan_id="test", tenant_id="t")
    g.add_node(AttackNode(id="ep", node_type="entrypoint", label="attacker", artifact_ref=""))
    g.add_node(AttackNode(id="svc1", node_type="service", label="https:443", artifact_ref="r1",
                           properties={"artifact_type": "services"}))
    g.add_node(AttackNode(id="ep1", node_type="endpoint", label="/api/login", artifact_ref="r2",
                           properties={"artifact_type": "endpoints"}))
    g.add_node(AttackNode(id="vuln1", node_type="vulnerability", label="SQLi on /api/login", artifact_ref="r3",
                           properties={"artifact_type": "vulnerabilities"}))
    g.add_node(AttackNode(id="cred1", node_type="credential", label="admin:password", artifact_ref="r4",
                           properties={"artifact_type": "credential_leak"}))
    g.add_node(AttackNode(id="priv1", node_type="privilege", label="database_access", artifact_ref="r5",
                           properties={"artifact_type": "database_access"}))
    # Edges: ep → svc → ep1 → vuln → cred → priv
    g.add_edge(AttackEdge(source="ep", target="svc1", edge_type="discovery"))
    g.add_edge(AttackEdge(source="svc1", target="ep1", edge_type="discovery"))
    g.add_edge(AttackEdge(source="ep1", target="vuln1", edge_type="discovery"))
    g.add_edge(AttackEdge(source="vuln1", target="cred1", edge_type="exploit"))
    g.add_edge(AttackEdge(source="cred1", target="priv1", edge_type="lateral_movement"))
    return g


# ═══════════════════════════════════════════════════════════════════
# 1. Attack Planner
# ═══════════════════════════════════════════════════════════════════


def test_planner_ranks_paths():
    from app.engine.attack_planner import AttackPlanner
    planner = AttackPlanner(_make_graph())
    ranked = planner.plan()
    assert len(ranked) > 0
    # Paths should be sorted by score descending
    scores = [p.score for p in ranked]
    assert scores == sorted(scores, reverse=True)


def test_planner_scores_have_factors():
    from app.engine.attack_planner import AttackPlanner
    ranked = AttackPlanner(_make_graph()).plan()
    for p in ranked:
        assert "exploit_probability" in p.factors
        assert "privilege_potential" in p.factors
        assert "chain_efficiency" in p.factors
        assert "novelty" in p.factors


def test_planner_paths_end_at_targets():
    from app.engine.attack_planner import AttackPlanner
    ranked = AttackPlanner(_make_graph()).plan()
    g = _make_graph()
    for p in ranked:
        last = p.nodes[-1]
        assert g.nodes[last].node_type in {"privilege", "credential"}


def test_planner_to_dict():
    from app.engine.attack_planner import AttackPlanner
    ranked = AttackPlanner(_make_graph()).plan()
    d = ranked[0].to_dict()
    assert "score" in d
    assert "factors" in d


def test_planner_mark_attempted():
    from app.engine.attack_planner import AttackPlanner
    planner = AttackPlanner(_make_graph())
    ranked = planner.plan()
    path_key = ":".join(ranked[0].nodes)
    planner.mark_attempted(path_key)
    # Re-plan: novelty should be 0 for that path
    ranked2 = planner.plan()
    # The marked path should have novelty=0
    for p in ranked2:
        key = ":".join(p.nodes)
        if key == path_key:
            assert p.factors["novelty"] == 0.0


# ═══════════════════════════════════════════════════════════════════
# 2. Action Selector
# ═══════════════════════════════════════════════════════════════════


def test_selector_selects_actions():
    from app.engine.action_selector import ActionSelector
    selector = ActionSelector(_make_graph())
    actions = selector.select()
    assert len(actions) > 0


def test_selector_action_types():
    from app.engine.action_selector import ActionSelector
    actions = ActionSelector(_make_graph()).select()
    types = {a.action_type for a in actions}
    # Should include at least one exploit or recon action
    assert len(types) > 0


def test_selector_sorted_by_priority():
    from app.engine.action_selector import ActionSelector
    actions = ActionSelector(_make_graph()).select()
    priorities = [a.priority for a in actions]
    assert priorities == sorted(priorities, reverse=True)


def test_selector_to_dict():
    from app.engine.action_selector import ActionSelector
    actions = ActionSelector(_make_graph()).select()
    d = actions[0].to_dict()
    assert "action_type" in d
    assert "priority" in d


def test_selector_adds_refinement_when_vulns_exist():
    from app.engine.action_selector import ActionSelector
    actions = ActionSelector(_make_graph()).select(max_actions=10)
    refine = [a for a in actions if a.action_type == "refine_exploit"]
    assert len(refine) > 0


# ═══════════════════════════════════════════════════════════════════
# 3. Budget Manager
# ═══════════════════════════════════════════════════════════════════


def test_budget_initial_state():
    from app.engine.budget_manager import BudgetManager
    mgr = BudgetManager()
    assert mgr.total_allocated == 0
    assert not mgr.budget_exhausted


def test_budget_allocate_and_release():
    from app.engine.budget_manager import BudgetManager
    mgr = BudgetManager()
    assert mgr.can_allocate("exploit")
    assert mgr.allocate("exploit")
    assert mgr.total_allocated == 1
    mgr.release("exploit")
    assert mgr.total_allocated == 0


def test_budget_exhaustion():
    from app.engine.budget_manager import BudgetManager, BudgetConfig
    mgr = BudgetManager(BudgetConfig(max_exploit_chains=2, max_total_tasks=3))
    mgr.allocate("exploit")
    mgr.allocate("exploit")
    assert not mgr.can_allocate("exploit")
    # But can still allocate recon
    assert mgr.can_allocate("recon")


def test_budget_global_cap():
    from app.engine.budget_manager import BudgetManager, BudgetConfig
    mgr = BudgetManager(BudgetConfig(max_total_tasks=3))
    mgr.allocate("exploit")
    mgr.allocate("recon")
    mgr.allocate("exploration")
    assert mgr.budget_exhausted
    assert not mgr.can_allocate("refinement")


def test_budget_filter_actions():
    from app.engine.budget_manager import BudgetManager, BudgetConfig
    from app.engine.action_selector import ActionSelector
    mgr = BudgetManager(BudgetConfig(max_exploit_chains=0))
    actions = ActionSelector(_make_graph()).select()
    filtered = mgr.filter_by_budget(actions)
    for a in filtered:
        assert a.action_type != "exploit_chain"


def test_budget_summary():
    from app.engine.budget_manager import BudgetManager
    mgr = BudgetManager()
    mgr.allocate("exploit", 3)
    s = mgr.summary()
    assert s["total_allocated"] == 3
    assert "categories" in s


def test_budget_reset():
    from app.engine.budget_manager import BudgetManager
    mgr = BudgetManager()
    mgr.allocate("exploit", 5)
    mgr.reset()
    assert mgr.total_allocated == 0


# ═══════════════════════════════════════════════════════════════════
# 4. Feedback Controller
# ═══════════════════════════════════════════════════════════════════


def test_feedback_credential_triggers():
    from app.engine.feedback_controller import FeedbackController, FeedbackEvent
    ctrl = FeedbackController()
    triggers = ctrl.process(FeedbackEvent(
        event_type="credential_found",
        source_action="exploit:sqli",
    ))
    assert len(triggers) >= 2  # credential_spray + lateral_recon
    types = {t.trigger_type for t in triggers}
    assert "credential_spray" in types
    assert "lateral_recon" in types


def test_feedback_vuln_confirmed():
    from app.engine.feedback_controller import FeedbackController, FeedbackEvent
    ctrl = FeedbackController()
    triggers = ctrl.process(FeedbackEvent(
        event_type="vulnerability_confirmed",
        source_action="heuristic:sqli",
    ))
    assert any(t.trigger_type == "exploit_escalation" for t in triggers)


def test_feedback_access_gained():
    from app.engine.feedback_controller import FeedbackController, FeedbackEvent
    ctrl = FeedbackController()
    triggers = ctrl.process(FeedbackEvent(
        event_type="access_gained",
        source_action="exploit:cred_reuse",
    ))
    types = {t.trigger_type for t in triggers}
    assert "deep_scan" in types
    assert "lateral_recon" in types


def test_feedback_exploit_failed():
    from app.engine.feedback_controller import FeedbackController, FeedbackEvent
    ctrl = FeedbackController()
    triggers = ctrl.process(FeedbackEvent(
        event_type="exploit_failed",
        source_action="exploit:sqli",
    ))
    assert any(t.trigger_type == "surface_expansion" for t in triggers)


def test_feedback_batch_processing():
    from app.engine.feedback_controller import FeedbackController, FeedbackEvent
    ctrl = FeedbackController()
    events = [
        FeedbackEvent("credential_found", "action1"),
        FeedbackEvent("access_gained", "action2"),
    ]
    triggers = ctrl.process_batch(events)
    assert len(triggers) >= 4  # 2 from cred + 2 from access


def test_feedback_summary():
    from app.engine.feedback_controller import FeedbackController, FeedbackEvent
    ctrl = FeedbackController()
    ctrl.process(FeedbackEvent("credential_found", "a1"))
    ctrl.process(FeedbackEvent("exploit_failed", "a2"))
    s = ctrl.summary()
    assert s["total_events"] == 2
    assert s["total_triggers"] > 0


def test_feedback_to_dict():
    from app.engine.feedback_controller import FeedbackController, FeedbackEvent
    ctrl = FeedbackController()
    triggers = ctrl.process(FeedbackEvent("credential_found", "a1"))
    d = triggers[0].to_dict()
    assert "trigger_type" in d
    assert "priority" in d


# ═══════════════════════════════════════════════════════════════════
# 5. Full Pipeline Integration
# ═══════════════════════════════════════════════════════════════════


def test_full_reasoning_pipeline():
    """End-to-end: graph → plan → select → budget → feedback loop."""
    from app.engine.attack_planner import AttackPlanner
    from app.engine.action_selector import ActionSelector
    from app.engine.budget_manager import BudgetManager
    from app.engine.feedback_controller import FeedbackController, FeedbackEvent

    graph = _make_graph()

    # 1 — Plan
    planner = AttackPlanner(graph)
    ranked = planner.plan()
    assert len(ranked) > 0

    # 2 — Select actions
    selector = ActionSelector(graph)
    actions = selector.select()
    assert len(actions) > 0

    # 3 — Budget filter
    mgr = BudgetManager()
    filtered = mgr.filter_by_budget(actions)
    assert len(filtered) > 0
    for a in filtered:
        cat = {"exploit_chain": "exploit", "deeper_recon": "recon",
               "expand_exploration": "exploration", "refine_exploit": "refinement"}.get(a.action_type, "exploration")
        mgr.allocate(cat)

    assert mgr.total_allocated > 0

    # 4 — Simulate feedback from executed action
    ctrl = FeedbackController()
    triggers = ctrl.process(FeedbackEvent(
        event_type="credential_found",
        source_action=actions[0].action_id,
        artifacts={"credential": "admin:password"},
    ))
    assert len(triggers) > 0

    # 5 — Budget allows follow-up
    for t in triggers[:2]:
        cat = "recon" if "recon" in t.trigger_type else "exploit"
        assert mgr.can_allocate(cat)


def test_reasoning_loop_with_graph_evolution():
    """Simulate attack graph evolving and reasoning engine adapting."""
    from app.engine.action_selector import ActionSelector
    from app.engine.feedback_controller import FeedbackController, FeedbackEvent

    graph = _make_graph()
    ctrl = FeedbackController()

    # Round 1: initial actions
    actions1 = ActionSelector(graph).select()
    assert len(actions1) > 0

    # Simulate: credential found → feedback
    triggers = ctrl.process(FeedbackEvent("credential_found", "action1"))
    assert len(triggers) > 0

    # Graph evolves: new service discovered
    graph.add_node(AttackNode(id="svc_internal", node_type="service", label="ssh:22",
                               artifact_ref="r10", properties={"artifact_type": "services"}))
    graph.add_edge(AttackEdge(source="cred1", target="svc_internal", edge_type="credential_usage"))

    # Round 2: new actions after graph update
    actions2 = ActionSelector(graph).select()
    assert len(actions2) > 0

    # Summary
    assert ctrl.event_count == 1


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
