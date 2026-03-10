"""MOD-10 Autonomous Recon Planner tests — validates asset analyzer,
recon actions, planner, coverage tracker, and exploration integration.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_recon_planner.py -v
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


# ═══════════════════════════════════════════════════════════════════
# 1. Recon Asset Analyzer
# ═══════════════════════════════════════════════════════════════════


def test_analyzer_classifies_subdomain():
    from app.engine.recon_asset_analyzer import ReconAssetAnalyzer
    g = _make_graph()
    analyzer = ReconAssetAnalyzer(g)
    assets = analyzer.analyze()
    subdomain = [a for a in assets if a.node_id == "a1"]
    assert len(subdomain) == 1
    assert subdomain[0].asset_class == "subdomain"


def test_analyzer_classifies_web_service():
    from app.engine.recon_asset_analyzer import ReconAssetAnalyzer
    g = _make_graph()
    analyzer = ReconAssetAnalyzer(g)
    assets = analyzer.analyze()
    web = [a for a in assets if a.node_id == "s1"]
    assert len(web) == 1
    assert web[0].asset_class == "web_service"


def test_analyzer_classifies_network_service():
    from app.engine.recon_asset_analyzer import ReconAssetAnalyzer
    g = _make_graph()
    analyzer = ReconAssetAnalyzer(g)
    assets = analyzer.analyze()
    net = [a for a in assets if a.node_id == "s2"]
    assert len(net) == 1
    assert net[0].asset_class == "network_service"


def test_analyzer_classifies_api_endpoint():
    from app.engine.recon_asset_analyzer import ReconAssetAnalyzer
    g = _make_graph()
    analyzer = ReconAssetAnalyzer(g)
    assets = analyzer.analyze()
    api = [a for a in assets if a.node_id == "e1"]
    assert len(api) == 1
    assert api[0].asset_class == "api_endpoint"


def test_analyzer_classifies_web_endpoint():
    from app.engine.recon_asset_analyzer import ReconAssetAnalyzer
    g = _make_graph()
    analyzer = ReconAssetAnalyzer(g)
    assets = analyzer.analyze()
    web_ep = [a for a in assets if a.node_id == "e2"]
    assert len(web_ep) == 1
    assert web_ep[0].asset_class == "web_endpoint"


def test_analyzer_skips_entrypoint():
    from app.engine.recon_asset_analyzer import ReconAssetAnalyzer
    g = _make_graph()
    analyzer = ReconAssetAnalyzer(g)
    assets = analyzer.analyze()
    entrypoints = [a for a in assets if a.node_id == "ep"]
    assert len(entrypoints) == 0


def test_analyzer_asset_to_dict():
    from app.engine.recon_asset_analyzer import ReconAssetAnalyzer
    g = _make_graph()
    analyzer = ReconAssetAnalyzer(g)
    d = analyzer.analyze()[0].to_dict()
    assert "asset_class" in d
    assert "node_id" in d


# ═══════════════════════════════════════════════════════════════════
# 2. Recon Action Library
# ═══════════════════════════════════════════════════════════════════


def test_recon_actions_load():
    from app.engine.recon_planner import ReconPlanner
    g = _make_graph()
    planner = ReconPlanner(g)
    assert len(planner.recon_actions) >= 13


def test_recon_actions_cover_subdomain():
    from app.engine.recon_planner import ReconPlanner
    g = _make_graph()
    planner = ReconPlanner(g)
    subdomain_actions = [a for a in planner.recon_actions if a.target_asset_class == "subdomain"]
    assert len(subdomain_actions) >= 2


def test_recon_actions_cover_web_service():
    from app.engine.recon_planner import ReconPlanner
    g = _make_graph()
    planner = ReconPlanner(g)
    web_actions = [a for a in planner.recon_actions if a.target_asset_class == "web_service"]
    assert len(web_actions) >= 2


def test_recon_actions_cover_network_service():
    from app.engine.recon_planner import ReconPlanner
    g = _make_graph()
    planner = ReconPlanner(g)
    net_actions = [a for a in planner.recon_actions if a.target_asset_class == "network_service"]
    assert len(net_actions) >= 2


# ═══════════════════════════════════════════════════════════════════
# 3. Recon Coverage Tracker
# ═══════════════════════════════════════════════════════════════════


def test_memory_tracks_explored():
    from app.engine.recon_memory import ReconMemory
    mem = ReconMemory()
    assert not mem.has_explored("a1", "subdomain_analysis")
    mem.record("a1", "subdomain_analysis", "httpx")
    assert mem.has_explored("a1", "subdomain_analysis")


def test_memory_coverage_list():
    from app.engine.recon_memory import ReconMemory
    mem = ReconMemory()
    mem.record("a1", "subdomain_analysis", "httpx")
    mem.record("a1", "subdomain_takeover_check", "custom_poc")
    assert "subdomain_analysis" in mem.get_coverage("a1")
    assert "subdomain_takeover_check" in mem.get_coverage("a1")


def test_memory_summary():
    from app.engine.recon_memory import ReconMemory
    mem = ReconMemory()
    mem.record("a1", "subdomain_analysis", "httpx")
    mem.record("a2", "service_fingerprint", "nmap")
    s = mem.summary()
    assert s["total_records"] == 2
    assert s["unique_assets"] == 2


# ═══════════════════════════════════════════════════════════════════
# 4. Recon Planner
# ═══════════════════════════════════════════════════════════════════


def test_planner_generates_hypotheses():
    from app.engine.recon_planner import ReconPlanner
    g = _make_graph()
    planner = ReconPlanner(g)
    hyps = planner.plan()
    assert len(hyps) > 0


def test_planner_subdomain_triggers_recon():
    from app.engine.recon_planner import ReconPlanner
    g = _make_graph()
    planner = ReconPlanner(g)
    hyps = planner.plan()
    subdomain_recon = [h for h in hyps if h.target_node_id == "a1" and "recon" in h.hypothesis_id]
    assert len(subdomain_recon) > 0


def test_planner_service_triggers_fingerprint():
    from app.engine.recon_planner import ReconPlanner
    g = _make_graph()
    planner = ReconPlanner(g)
    hyps = planner.plan()
    svc_recon = [h for h in hyps if h.target_node_id == "s2" and "recon" in h.hypothesis_id]
    assert len(svc_recon) > 0


def test_planner_respects_coverage():
    from app.engine.recon_planner import ReconPlanner
    from app.engine.recon_memory import ReconMemory
    g = _make_graph()
    mem = ReconMemory()
    planner = ReconPlanner(g, memory=mem)
    hyps1 = planner.plan()

    # Record all as explored
    for h in hyps1:
        mem.record(h.target_node_id, h.config.get("recon_action", ""), h.tool)

    hyps2 = planner.plan()
    assert len(hyps2) < len(hyps1)


def test_planner_max_per_asset():
    from app.engine.recon_planner import ReconPlanner
    g = _make_graph()
    planner = ReconPlanner(g)
    hyps = planner.plan(max_per_asset=1)
    from collections import Counter
    by_target = Counter(h.target_node_id for h in hyps)
    for count in by_target.values():
        assert count <= 1


def test_planner_hypotheses_have_recon_metadata():
    from app.engine.recon_planner import ReconPlanner
    g = _make_graph()
    planner = ReconPlanner(g)
    for h in planner.plan():
        assert h.config.get("recon_action")
        assert h.config.get("asset_class")
        assert h.config.get("no_persist") is True


# ═══════════════════════════════════════════════════════════════════
# 5. ExplorationEngine Integration
# ═══════════════════════════════════════════════════════════════════


def test_exploration_engine_uses_recon_planner():
    import inspect
    from app.engine.exploration_engine import ExplorationEngine
    source = inspect.getsource(ExplorationEngine)
    assert "ReconPlanner" in source
    assert "ReconMemory" in source


def test_exploration_engine_has_recon_hypotheses():
    import inspect
    from app.engine.exploration_engine import ExplorationEngine
    source = inspect.getsource(ExplorationEngine.explore)
    assert "recon_hypotheses" in source


# ═══════════════════════════════════════════════════════════════════
# 6. Full Pipeline
# ═══════════════════════════════════════════════════════════════════


def test_full_recon_pipeline():
    """End-to-end: assets → recon actions → hypotheses → scored."""
    from app.engine.recon_planner import ReconPlanner
    from app.engine.exploration_scorer import ExplorationScorer

    g = _make_graph()
    planner = ReconPlanner(g)
    hyps = planner.plan()
    assert len(hyps) > 0

    scorer = ExplorationScorer(g)
    scored = scorer.score(hyps, min_score=0.0)
    assert len(scored) > 0


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
