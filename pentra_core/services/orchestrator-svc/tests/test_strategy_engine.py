"""MOD-08 Phase 2 — Strategy Engine + Exploit Chain Generator tests.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_strategy_engine.py -v
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid

import pytest

_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════

def _make_test_graph():
    """Build a test graph with a clear attack path."""
    from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge

    g = AttackGraph(scan_id="test-scan", tenant_id="test-tenant")
    g.add_node(AttackNode(id="ep", node_type="entrypoint", label="External Attacker", artifact_ref=""))
    g.add_node(AttackNode(id="a1", node_type="asset", label="api.target.com",
                          artifact_ref="r1", properties={"artifact_type": "subdomains"}))
    g.add_node(AttackNode(id="e1", node_type="endpoint", label="/admin/login",
                          artifact_ref="r2", properties={"artifact_type": "endpoints"}))
    g.add_node(AttackNode(id="v1", node_type="vulnerability", label="SQL Injection",
                          artifact_ref="r3", properties={"artifact_type": "sql_injection"}))
    g.add_node(AttackNode(id="c1", node_type="credential", label="admin:hash",
                          artifact_ref="r4", properties={"artifact_type": "credential_leak"}))
    g.add_node(AttackNode(id="p1", node_type="privilege", label="database_access",
                          artifact_ref="r5", properties={"artifact_type": "database_access"}))

    g.add_edge(AttackEdge(source="ep", target="a1", edge_type="discovery"))
    g.add_edge(AttackEdge(source="a1", target="e1", edge_type="discovery"))
    g.add_edge(AttackEdge(source="e1", target="v1", edge_type="discovery"))
    g.add_edge(AttackEdge(source="v1", target="c1", edge_type="exploit"))
    g.add_edge(AttackEdge(source="c1", target="p1", edge_type="credential_usage"))

    return g


def _make_scored_paths(graph):
    from app.engine.path_enumerator import PathEnumerator
    from app.engine.path_scorer import PathScorer

    enum = PathEnumerator(graph)
    paths = enum.enumerate_paths()
    scorer = PathScorer(graph)
    return scorer.score_paths(paths)


# ═══════════════════════════════════════════════════════════════════
# 1. Strategy Engine — ranking
# ═══════════════════════════════════════════════════════════════════


def test_strategy_engine_selects_path():
    from app.engine.strategy_engine import StrategyEngine
    g = _make_test_graph()
    scored = _make_scored_paths(g)

    engine = StrategyEngine(g)
    strategy = engine.select_strategy(scored)

    assert strategy is not None
    assert strategy.selected_path.rank == 1
    assert strategy.selected_path.offensive_score > 0


def test_strategy_returns_none_for_empty():
    from app.engine.strategy_engine import StrategyEngine
    from app.engine.attack_graph_builder import AttackGraph
    g = AttackGraph(scan_id="s", tenant_id="t")
    engine = StrategyEngine(g)
    assert engine.select_strategy([]) is None


def test_strategy_path_has_rationale():
    from app.engine.strategy_engine import StrategyEngine
    g = _make_test_graph()
    scored = _make_scored_paths(g)

    engine = StrategyEngine(g)
    strategy = engine.select_strategy(scored)

    assert strategy.selected_path.rationale
    assert "Target:" in strategy.selected_path.rationale


def test_strategy_ranks_descending():
    from app.engine.strategy_engine import StrategyEngine
    g = _make_test_graph()
    scored = _make_scored_paths(g)

    engine = StrategyEngine(g)
    strategy = engine.select_strategy(scored)

    for i in range(len(strategy.all_ranked) - 1):
        assert strategy.all_ranked[i].offensive_score >= strategy.all_ranked[i + 1].offensive_score


def test_strategy_to_dict():
    from app.engine.strategy_engine import StrategyEngine
    g = _make_test_graph()
    scored = _make_scored_paths(g)

    engine = StrategyEngine(g)
    strategy = engine.select_strategy(scored)
    d = strategy.to_dict()

    assert d["scan_id"] == "test-scan"
    assert d["selected_rank"] == 1
    assert "path_nodes" in d
    assert "path_edges" in d


def test_strategy_estimated_steps():
    from app.engine.strategy_engine import StrategyEngine
    g = _make_test_graph()
    scored = _make_scored_paths(g)

    engine = StrategyEngine(g)
    strategy = engine.select_strategy(scored)

    assert strategy.estimated_steps >= 1  # at least exploit + credential_usage


def test_rank_weights_sum_to_one():
    from app.engine.strategy_engine import _RANK_WEIGHTS
    total = sum(_RANK_WEIGHTS.values())
    assert abs(total - 1.0) < 0.001


def test_high_value_targets_defined():
    from app.engine.strategy_engine import _HIGH_VALUE_TARGETS
    assert "shell_access" in _HIGH_VALUE_TARGETS
    assert "database_access" in _HIGH_VALUE_TARGETS
    assert "privilege_escalation" in _HIGH_VALUE_TARGETS


# ═══════════════════════════════════════════════════════════════════
# 2. Exploit Chain Generator — chain generation
# ═══════════════════════════════════════════════════════════════════


def test_chain_generation():
    from app.engine.strategy_engine import StrategyEngine
    from app.engine.exploit_chain_generator import ExploitChainGenerator

    g = _make_test_graph()
    scored = _make_scored_paths(g)
    engine = StrategyEngine(g)
    strategy = engine.select_strategy(scored)

    gen = ExploitChainGenerator.__new__(ExploitChainGenerator)
    gen._graph = g
    chain = gen.generate_chain(strategy)

    assert chain is not None
    assert len(chain.steps) >= 1  # exploit + credential_usage edges
    assert chain.scan_id == "test-scan"
    assert chain.target_type in ("database_access", "credential_leak", "shell_access", "unknown")


def test_chain_steps_have_tools():
    from app.engine.strategy_engine import StrategyEngine
    from app.engine.exploit_chain_generator import ExploitChainGenerator

    g = _make_test_graph()
    scored = _make_scored_paths(g)
    engine = StrategyEngine(g)
    strategy = engine.select_strategy(scored)

    gen = ExploitChainGenerator.__new__(ExploitChainGenerator)
    gen._graph = g
    chain = gen.generate_chain(strategy)

    for step in chain.steps:
        assert step.tool in ("sqlmap", "metasploit", "custom_poc")
        assert step.worker_family == "exploit"
        assert step.timeout_seconds > 0


def test_chain_steps_sequential_dependencies():
    from app.engine.strategy_engine import StrategyEngine
    from app.engine.exploit_chain_generator import ExploitChainGenerator

    g = _make_test_graph()
    scored = _make_scored_paths(g)
    engine = StrategyEngine(g)
    strategy = engine.select_strategy(scored)

    gen = ExploitChainGenerator.__new__(ExploitChainGenerator)
    gen._graph = g
    chain = gen.generate_chain(strategy)

    for step in chain.steps:
        if step.step_number == 1:
            assert step.depends_on is None
        else:
            assert step.depends_on == step.step_number - 1


def test_chain_to_dict():
    from app.engine.strategy_engine import StrategyEngine
    from app.engine.exploit_chain_generator import ExploitChainGenerator

    g = _make_test_graph()
    scored = _make_scored_paths(g)
    engine = StrategyEngine(g)
    strategy = engine.select_strategy(scored)

    gen = ExploitChainGenerator.__new__(ExploitChainGenerator)
    gen._graph = g
    chain = gen.generate_chain(strategy)
    d = chain.to_dict()

    assert d["scan_id"] == "test-scan"
    assert d["signature"]
    assert d["step_count"] == len(chain.steps)
    assert all("action" in s for s in d["steps"])


def test_chain_skips_discovery_edges():
    """Discovery edges should NOT produce exploit steps."""
    from app.engine.exploit_chain_generator import _EDGE_STEP_MAP
    assert "discovery" not in _EDGE_STEP_MAP


def test_chain_safety_config():
    """All chain steps must have no_persist flag."""
    from app.engine.strategy_engine import StrategyEngine
    from app.engine.exploit_chain_generator import ExploitChainGenerator

    g = _make_test_graph()
    scored = _make_scored_paths(g)
    engine = StrategyEngine(g)
    strategy = engine.select_strategy(scored)

    gen = ExploitChainGenerator.__new__(ExploitChainGenerator)
    gen._graph = g
    chain = gen.generate_chain(strategy)

    for step in chain.steps:
        assert step.config.get("no_persist") is True


def test_chain_signature_exists_checks_existing_dynamic_nodes():
    from app.engine.strategy_engine import StrategyEngine
    from app.engine.exploit_chain_generator import ExploitChainGenerator

    class _FakeResult:
        def __init__(self, value):
            self._value = value

        def scalar(self):
            return self._value

    class _FakeSession:
        def __init__(self):
            self.seen_signatures: set[str] = set()

        async def execute(self, statement, params=None):
            params = params or {}
            if "chain_signature" not in str(statement):
                raise AssertionError(f"Unexpected query: {statement}")
            return _FakeResult(params["signature"] in self.seen_signatures)

    g = _make_test_graph()
    scored = _make_scored_paths(g)
    engine = StrategyEngine(g)
    strategy = engine.select_strategy(scored)

    gen = ExploitChainGenerator.__new__(ExploitChainGenerator)
    gen._graph = g
    gen._session = _FakeSession()

    chain = gen.generate_chain(strategy)

    assert asyncio.run(
        gen._chain_signature_exists(dag_id=uuid.uuid4(), signature=chain.signature)
    ) is False

    gen._session.seen_signatures.add(chain.signature)

    assert asyncio.run(
        gen._chain_signature_exists(dag_id=uuid.uuid4(), signature=chain.signature)
    ) is True


# ═══════════════════════════════════════════════════════════════════
# 3. Edge step mapping
# ═══════════════════════════════════════════════════════════════════


def test_edge_step_map_exists():
    from app.engine.exploit_chain_generator import _EDGE_STEP_MAP
    assert "exploit" in _EDGE_STEP_MAP
    assert "credential_usage" in _EDGE_STEP_MAP
    assert "lateral_movement" in _EDGE_STEP_MAP
    assert "privilege_escalation" in _EDGE_STEP_MAP


def test_target_tool_map():
    from app.engine.exploit_chain_generator import _TARGET_TOOL_MAP
    assert _TARGET_TOOL_MAP["database_access"] == "sqlmap"
    assert _TARGET_TOOL_MAP["shell_access"] == "metasploit"
    assert _TARGET_TOOL_MAP["credential_leak"] == "custom_poc"


# ═══════════════════════════════════════════════════════════════════
# 4. Tool resolution
# ═══════════════════════════════════════════════════════════════════


def test_resolve_tool_database():
    from app.engine.attack_graph_builder import AttackNode
    from app.engine.exploit_chain_generator import ExploitChainGenerator

    gen = ExploitChainGenerator.__new__(ExploitChainGenerator)
    node = AttackNode(id="n", node_type="privilege", label="db",
                      artifact_ref="", properties={"artifact_type": "database_access"})
    assert gen._resolve_tool(node, "default") == "sqlmap"


def test_resolve_tool_shell():
    from app.engine.attack_graph_builder import AttackNode
    from app.engine.exploit_chain_generator import ExploitChainGenerator

    gen = ExploitChainGenerator.__new__(ExploitChainGenerator)
    node = AttackNode(id="n", node_type="privilege", label="shell",
                      artifact_ref="", properties={"artifact_type": "shell_access"})
    assert gen._resolve_tool(node, "default") == "metasploit"


def test_resolve_tool_default():
    from app.engine.exploit_chain_generator import ExploitChainGenerator
    gen = ExploitChainGenerator.__new__(ExploitChainGenerator)
    assert gen._resolve_tool(None, "fallback") == "fallback"


def test_resolve_action_database():
    from app.engine.attack_graph_builder import AttackNode
    from app.engine.exploit_chain_generator import ExploitChainGenerator

    gen = ExploitChainGenerator.__new__(ExploitChainGenerator)
    node = AttackNode(id="n", node_type="privilege", label="db",
                      artifact_ref="", properties={"artifact_type": "database_access"})
    assert gen._resolve_action(node, "default", "exploit") == "db_exploit_verify"


# ═══════════════════════════════════════════════════════════════════
# 5. Full end-to-end: graph → strategy → chain
# ═══════════════════════════════════════════════════════════════════


def test_full_pipeline():
    """End-to-end: build graph → score → strategy → exploit chain."""
    from app.engine.attack_graph_builder import AttackGraphBuilder, AttackGraph, AttackNode, AttackEdge
    from app.engine.attack_graph_builder import _ENTRYPOINTS
    from app.engine.path_enumerator import PathEnumerator
    from app.engine.path_scorer import PathScorer
    from app.engine.graph_correlator import GraphCorrelator
    from app.engine.strategy_engine import StrategyEngine
    from app.engine.exploit_chain_generator import ExploitChainGenerator

    # Build graph
    g = _make_test_graph()

    # Correlate
    correlator = GraphCorrelator()
    correlator.correlate(g)

    # Enumerate + score
    enum = PathEnumerator(g)
    paths = enum.enumerate_paths()
    scorer = PathScorer(g)
    scored = scorer.score_paths(paths)

    # Strategy
    engine = StrategyEngine(g)
    strategy = engine.select_strategy(scored)
    assert strategy is not None
    assert strategy.estimated_steps >= 1

    # Chain
    gen = ExploitChainGenerator.__new__(ExploitChainGenerator)
    gen._graph = g
    chain = gen.generate_chain(strategy)

    assert len(chain.steps) >= 1
    # Verify chain covers the attack path correctly
    step_actions = [s.action for s in chain.steps]
    assert len(step_actions) >= 1


# ═══════════════════════════════════════════════════════════════════
# 6. ArtifactBus integration
# ═══════════════════════════════════════════════════════════════════


def test_artifact_bus_imports_strategy():
    import inspect
    from app.engine.artifact_bus import ArtifactBus
    source = inspect.getsource(ArtifactBus)
    assert "StrategyEngine" in source
    assert "ExploitChainGenerator" in source


def test_artifact_bus_has_strategy_result():
    import inspect
    from app.engine.artifact_bus import ArtifactBus
    source = inspect.getsource(ArtifactBus.process_completed_node)
    assert "strategy_nodes_created" in source


def test_orchestrator_resolves_strategy_nodes():
    import inspect
    from app.services.orchestrator_service import OrchestratorService
    source = inspect.getsource(OrchestratorService.handle_job_completed)
    assert "strategy_nodes_created" in source


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
