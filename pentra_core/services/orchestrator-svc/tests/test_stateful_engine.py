"""MOD-11.6 Stateful Interaction Engine tests — validates session manager,
interaction mapper, state graph, workflow mutator, and behavior analyzer.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_stateful_engine.py -v
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
    g.add_node(AttackNode(id="e1", node_type="endpoint", label="/api/login",
                          artifact_ref="r1", properties={"artifact_type": "endpoints"}))
    g.add_node(AttackNode(id="e2", node_type="endpoint", label="/api/users/profile",
                          artifact_ref="r2", properties={"artifact_type": "endpoints"}))
    g.add_node(AttackNode(id="e3", node_type="endpoint", label="/api/orders/create",
                          artifact_ref="r3", properties={"artifact_type": "endpoints"}))
    g.add_node(AttackNode(id="e4", node_type="endpoint", label="/api/orders/delete",
                          artifact_ref="r4", properties={"artifact_type": "endpoints"}))
    g.add_node(AttackNode(id="e5", node_type="endpoint", label="/admin/dashboard",
                          artifact_ref="r5", properties={"artifact_type": "endpoints"}))
    g.add_node(AttackNode(id="e6", node_type="endpoint", label="/api/checkout?price=100",
                          artifact_ref="r6", properties={"artifact_type": "endpoints"}))
    g.add_node(AttackNode(id="e7", node_type="endpoint", label="/api/register",
                          artifact_ref="r7", properties={"artifact_type": "endpoints"}))
    return g


# ═══════════════════════════════════════════════════════════════════
# 1. Session Manager
# ═══════════════════════════════════════════════════════════════════


def test_session_default_created():
    from app.engine.session_manager import SessionManager
    mgr = SessionManager()
    assert mgr.session_count >= 1
    assert mgr.get_default().session_type == "unauthenticated"


def test_session_create_multiple():
    from app.engine.session_manager import SessionManager
    mgr = SessionManager()
    s1 = mgr.create_session("user_session", user_context={"username": "alice"})
    s2 = mgr.create_session("admin_session", user_context={"username": "admin"})
    assert mgr.session_count >= 3
    assert s1.session_type == "user_session"
    assert s2.session_type == "admin_session"


def test_session_set_token_authenticates():
    from app.engine.session_manager import SessionManager
    mgr = SessionManager()
    s = mgr.create_session("user_session")
    assert s.auth_state == "none"
    mgr.set_token(s.session_id, "jwt", "eyJhbGciOiJIUzI1NiJ9")
    assert s.auth_state == "authenticated"


def test_session_auth_headers():
    from app.engine.session_manager import SessionManager
    mgr = SessionManager()
    s = mgr.create_session("user_session")
    mgr.set_token(s.session_id, "jwt", "eyJ_test_token")
    mgr.set_token(s.session_id, "csrf", "csrf_token_123")
    mgr.set_cookie(s.session_id, "session_id", "abc123")
    headers = mgr.get_auth_headers(s.session_id)
    assert "Authorization" in headers
    assert "Bearer eyJ_test_token" in headers["Authorization"]
    assert "X-CSRF-Token" in headers
    assert "Cookie" in headers


def test_session_elevate():
    from app.engine.session_manager import SessionManager
    mgr = SessionManager()
    s = mgr.create_session("user_session")
    mgr.elevate_session(s.session_id)
    assert s.auth_state == "elevated"
    assert s.session_type == "admin_session"


def test_session_by_type():
    from app.engine.session_manager import SessionManager
    mgr = SessionManager()
    mgr.create_session("user_session")
    mgr.create_session("user_session")
    assert len(mgr.get_sessions_by_type("user_session")) == 2


def test_session_summary():
    from app.engine.session_manager import SessionManager
    mgr = SessionManager()
    mgr.create_session("user_session")
    s = mgr.summary()
    assert s["total_sessions"] >= 2


def test_session_to_dict():
    from app.engine.session_manager import SessionManager
    mgr = SessionManager()
    d = mgr.get_default().to_dict()
    assert "session_type" in d
    assert "auth_state" in d


# ═══════════════════════════════════════════════════════════════════
# 2. Interaction Mapper
# ═══════════════════════════════════════════════════════════════════


def test_mapper_finds_auth_group():
    from app.engine.interaction_mapper import InteractionMapper
    g = _make_graph()
    mapper = InteractionMapper(g)
    groups = mapper.map_interactions()
    auth = [gr for gr in groups if gr.group_type == "auth"]
    assert len(auth) == 1


def test_mapper_finds_crud_group():
    from app.engine.interaction_mapper import InteractionMapper
    g = _make_graph()
    mapper = InteractionMapper(g)
    groups = mapper.map_interactions()
    crud = [gr for gr in groups if gr.group_type == "crud"]
    assert len(crud) == 1


def test_mapper_finds_admin_group():
    from app.engine.interaction_mapper import InteractionMapper
    g = _make_graph()
    mapper = InteractionMapper(g)
    groups = mapper.map_interactions()
    admin = [gr for gr in groups if gr.group_type == "admin"]
    assert len(admin) == 1


def test_mapper_finds_payment_group():
    from app.engine.interaction_mapper import InteractionMapper
    g = _make_graph()
    mapper = InteractionMapper(g)
    groups = mapper.map_interactions()
    payment = [gr for gr in groups if gr.group_type == "payment"]
    assert len(payment) == 1


def test_mapper_generates_interactions():
    from app.engine.interaction_mapper import InteractionMapper
    g = _make_graph()
    mapper = InteractionMapper(g)
    groups = mapper.map_interactions()
    total_interactions = sum(len(gr.interactions) for gr in groups)
    assert total_interactions > 0


def test_interaction_to_dict():
    from app.engine.interaction_mapper import InteractionMapper
    g = _make_graph()
    mapper = InteractionMapper(g)
    groups = mapper.map_interactions()
    for gr in groups:
        if gr.interactions:
            d = gr.interactions[0].to_dict()
            assert "relationship" in d
            break


# ═══════════════════════════════════════════════════════════════════
# 3. State Graph Builder
# ═══════════════════════════════════════════════════════════════════


def test_state_graph_builds_from_groups():
    from app.engine.interaction_mapper import InteractionMapper
    from app.engine.state_graph_builder import StateGraphBuilder
    g = _make_graph()
    mapper = InteractionMapper(g)
    groups = mapper.map_interactions()
    builder = StateGraphBuilder()
    graphs = builder.build(groups)
    assert len(graphs) > 0


def test_state_graph_has_states():
    from app.engine.interaction_mapper import InteractionMapper
    from app.engine.state_graph_builder import StateGraphBuilder
    g = _make_graph()
    groups = InteractionMapper(g).map_interactions()
    graphs = StateGraphBuilder().build(groups)
    for wf in graphs:
        assert wf.state_count >= 2


def test_state_graph_has_transitions():
    from app.engine.interaction_mapper import InteractionMapper
    from app.engine.state_graph_builder import StateGraphBuilder
    g = _make_graph()
    groups = InteractionMapper(g).map_interactions()
    graphs = StateGraphBuilder().build(groups)
    for wf in graphs:
        assert wf.transition_count > 0


def test_state_graph_has_initial_state():
    from app.engine.interaction_mapper import InteractionMapper
    from app.engine.state_graph_builder import StateGraphBuilder
    g = _make_graph()
    groups = InteractionMapper(g).map_interactions()
    graphs = StateGraphBuilder().build(groups)
    for wf in graphs:
        initial = [s for s in wf.states if s.state_type == "initial"]
        assert len(initial) == 1


def test_state_graph_to_dict():
    from app.engine.interaction_mapper import InteractionMapper
    from app.engine.state_graph_builder import StateGraphBuilder
    g = _make_graph()
    groups = InteractionMapper(g).map_interactions()
    graphs = StateGraphBuilder().build(groups)
    d = graphs[0].to_dict()
    assert "states" in d
    assert "transitions" in d


# ═══════════════════════════════════════════════════════════════════
# 4. Workflow Mutator
# ═══════════════════════════════════════════════════════════════════


def test_mutator_generates_hypotheses():
    from app.engine.interaction_mapper import InteractionMapper
    from app.engine.state_graph_builder import StateGraphBuilder
    from app.engine.workflow_mutator import WorkflowMutator
    g = _make_graph()
    groups = InteractionMapper(g).map_interactions()
    wf_graphs = StateGraphBuilder().build(groups)
    mutator = WorkflowMutator(g)
    hyps = mutator.mutate(wf_graphs)
    assert len(hyps) > 0


def test_mutator_hypotheses_have_workflow_metadata():
    from app.engine.interaction_mapper import InteractionMapper
    from app.engine.state_graph_builder import StateGraphBuilder
    from app.engine.workflow_mutator import WorkflowMutator
    g = _make_graph()
    groups = InteractionMapper(g).map_interactions()
    wf_graphs = StateGraphBuilder().build(groups)
    mutator = WorkflowMutator(g)
    for h in mutator.mutate(wf_graphs):
        assert h.config.get("workflow_mutation")
        assert h.config.get("workflow_type")
        assert h.config.get("no_persist") is True


def test_mutator_generates_skip_step():
    from app.engine.interaction_mapper import InteractionMapper
    from app.engine.state_graph_builder import StateGraphBuilder
    from app.engine.workflow_mutator import WorkflowMutator
    g = _make_graph()
    groups = InteractionMapper(g).map_interactions()
    wf_graphs = StateGraphBuilder().build(groups)
    mutator = WorkflowMutator(g)
    hyps = mutator.mutate(wf_graphs)
    skips = [h for h in hyps if h.config.get("workflow_mutation") == "skip_step"]
    assert len(skips) > 0


def test_mutator_generates_cross_session():
    from app.engine.interaction_mapper import InteractionMapper
    from app.engine.state_graph_builder import StateGraphBuilder
    from app.engine.workflow_mutator import WorkflowMutator
    g = _make_graph()
    groups = InteractionMapper(g).map_interactions()
    wf_graphs = StateGraphBuilder().build(groups)
    mutator = WorkflowMutator(g)
    hyps = mutator.mutate(wf_graphs)
    cross = [h for h in hyps if h.config.get("workflow_mutation") == "cross_session"]
    assert len(cross) > 0


def test_mutator_respects_max():
    from app.engine.interaction_mapper import InteractionMapper
    from app.engine.state_graph_builder import StateGraphBuilder
    from app.engine.workflow_mutator import WorkflowMutator
    g = _make_graph()
    groups = InteractionMapper(g).map_interactions()
    wf_graphs = StateGraphBuilder().build(groups)
    mutator = WorkflowMutator(g)
    hyps = mutator.mutate(wf_graphs, max_per_workflow=2)
    from collections import Counter
    by_wf = Counter(h.config.get("workflow_type") for h in hyps)
    for count in by_wf.values():
        assert count <= 2


# ═══════════════════════════════════════════════════════════════════
# 5. Behavior Analyzer
# ═══════════════════════════════════════════════════════════════════


def test_analyzer_detects_auth_bypass():
    from app.engine.behavior_analyzer import BehaviorAnalyzer
    analyzer = BehaviorAnalyzer()
    result = analyzer.analyze(
        response={"status_code": 200, "body": "Welcome to your dashboard with email and admin role"},
        mutation_config={"workflow_mutation": "cross_session", "workflow_type": "auth"},
    )
    assert result.verdict in ("confirmed", "likely")
    assert result.flaw_type in ("auth_bypass", "privilege_escalation")


def test_analyzer_detects_workflow_bypass():
    from app.engine.behavior_analyzer import BehaviorAnalyzer
    analyzer = BehaviorAnalyzer()
    result = analyzer.analyze(
        response={"status_code": 200, "body": "Order confirmed successfully with details and information"},
        mutation_config={"workflow_mutation": "skip_step", "workflow_type": "payment"},
    )
    assert result.verdict in ("confirmed", "likely")
    assert result.flaw_type == "workflow_bypass"


def test_analyzer_detects_idor():
    from app.engine.behavior_analyzer import BehaviorAnalyzer
    analyzer = BehaviorAnalyzer()
    result = analyzer.analyze(
        response={"status_code": 200, "body": "User profile: email alice@test.com, phone 555-1234, address 123 Main St"},
        mutation_config={"workflow_mutation": "modify_id", "workflow_type": "crud"},
    )
    assert result.verdict in ("confirmed", "likely")
    assert result.flaw_type == "idor"


def test_analyzer_negative_on_blocked():
    from app.engine.behavior_analyzer import BehaviorAnalyzer
    analyzer = BehaviorAnalyzer()
    result = analyzer.analyze(
        response={"status_code": 403, "body": "Forbidden"},
        mutation_config={"workflow_mutation": "cross_session", "workflow_type": "auth"},
    )
    assert result.verdict == "negative"


def test_analyzer_result_to_dict():
    from app.engine.behavior_analyzer import BehaviorAnalyzer
    analyzer = BehaviorAnalyzer()
    result = analyzer.analyze(
        response={"status_code": 200, "body": "ok"},
        mutation_config={"workflow_mutation": "repeat_step", "workflow_type": "crud"},
    )
    d = result.to_dict()
    assert "verdict" in d
    assert "flaw_type" in d


# ═══════════════════════════════════════════════════════════════════
# 6. Full Pipeline
# ═══════════════════════════════════════════════════════════════════


def test_full_stateful_pipeline():
    """End-to-end: graph → interactions → state graph → mutations → score."""
    from app.engine.interaction_mapper import InteractionMapper
    from app.engine.state_graph_builder import StateGraphBuilder
    from app.engine.workflow_mutator import WorkflowMutator
    from app.engine.exploration_scorer import ExplorationScorer

    g = _make_graph()
    groups = InteractionMapper(g).map_interactions()
    wf_graphs = StateGraphBuilder().build(groups)
    mutator = WorkflowMutator(g)
    hyps = mutator.mutate(wf_graphs)
    assert len(hyps) > 0

    scorer = ExplorationScorer(g)
    scored = scorer.score(hyps, min_score=0.0)
    assert len(scored) > 0


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
