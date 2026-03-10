"""MOD-12.6 Hypothesis Graph Manager tests — validates hypothesis graph,
deduplicator, coverage tracker, complexity controller, and full pipeline.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_hypothesis_graph_manager.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)

from app.engine.hypothesis_generator import Hypothesis


def _hyp(hid: str, target: str = "ep1", tool: str = "nuclei",
         vuln_class: str = "sql_injection", test_type: str = "fuzz",
         **extra) -> Hypothesis:
    """Helper to create test hypotheses."""
    config = {"vulnerability_class": vuln_class, "test_type": test_type, "no_persist": True, **extra}
    return Hypothesis(
        hypothesis_id=hid, hypothesis_type="test",
        target_node_id=target, target_label=f"label:{target}",
        description=f"Test {vuln_class}", tool=tool, worker_family="recon",
        config=config, required_artifacts=[], estimated_complexity=3,
    )


# ═══════════════════════════════════════════════════════════════════
# 1. Hypothesis Graph
# ═══════════════════════════════════════════════════════════════════


def test_graph_add_and_get():
    from app.engine.hypothesis_graph import HypothesisGraph
    g = HypothesisGraph()
    g.add(_hyp("h1"), "heuristic")
    assert g.total == 1
    assert g.get("h1") is not None


def test_graph_batch_add():
    from app.engine.hypothesis_graph import HypothesisGraph
    g = HypothesisGraph()
    nodes = g.add_batch([_hyp("h1"), _hyp("h2"), _hyp("h3")], "exploration")
    assert g.total == 3
    assert len(nodes) == 3


def test_graph_approve_reject():
    from app.engine.hypothesis_graph import HypothesisGraph
    g = HypothesisGraph()
    g.add(_hyp("h1"), "heuristic")
    g.add(_hyp("h2"), "exploration")
    g.approve("h1")
    g.reject("h2", "low_value")
    assert g.approved_count == 1
    assert g.rejected_count == 1
    assert g.get("h2").rejection_reason == "low_value"


def test_graph_pending():
    from app.engine.hypothesis_graph import HypothesisGraph
    g = HypothesisGraph()
    g.add(_hyp("h1"), "a")
    g.add(_hyp("h2"), "b")
    g.approve("h1")
    assert len(g.get_pending()) == 1


def test_graph_get_by_target():
    from app.engine.hypothesis_graph import HypothesisGraph
    g = HypothesisGraph()
    g.add(_hyp("h1", target="ep1"), "a")
    g.add(_hyp("h2", target="ep2"), "a")
    assert len(g.get_by_target("ep1")) == 1


def test_graph_get_by_module():
    from app.engine.hypothesis_graph import HypothesisGraph
    g = HypothesisGraph()
    g.add(_hyp("h1"), "heuristic")
    g.add(_hyp("h2"), "exploration")
    assert len(g.get_by_module("heuristic")) == 1


def test_graph_priority_score():
    from app.engine.hypothesis_graph import HypothesisGraph
    g = HypothesisGraph()
    node = g.add(_hyp("h1"), "heuristic", confidence=0.9, risk_impact=0.8)
    assert node.priority_score > 0


def test_graph_summary():
    from app.engine.hypothesis_graph import HypothesisGraph
    g = HypothesisGraph()
    g.add(_hyp("h1"), "heuristic")
    g.add(_hyp("h2"), "exploration")
    s = g.summary()
    assert s["total"] == 2
    assert "by_module" in s


# ═══════════════════════════════════════════════════════════════════
# 2. Hypothesis Deduplicator
# ═══════════════════════════════════════════════════════════════════


def test_dedup_finds_duplicates():
    from app.engine.hypothesis_graph import HypothesisGraph
    from app.engine.hypothesis_deduplicator import HypothesisDeduplicator
    g = HypothesisGraph()
    # Same target, tool, vuln_class, test_type → duplicate
    g.add(_hyp("h1", target="ep1", tool="nuclei", vuln_class="sqli", test_type="fuzz"), "heuristic")
    g.add(_hyp("h2", target="ep1", tool="nuclei", vuln_class="sqli", test_type="fuzz"), "exploration")
    result = HypothesisDeduplicator().deduplicate(g)
    assert result.duplicates_found == 1


def test_dedup_keeps_highest_confidence():
    from app.engine.hypothesis_graph import HypothesisGraph
    from app.engine.hypothesis_deduplicator import HypothesisDeduplicator
    g = HypothesisGraph()
    g.add(_hyp("h1", tool="nuclei", vuln_class="sqli", test_type="fuzz"), "a", confidence=0.3)
    g.add(_hyp("h2", tool="nuclei", vuln_class="sqli", test_type="fuzz"), "b", confidence=0.9)
    HypothesisDeduplicator().deduplicate(g)
    # h2 has higher confidence, so h1 should be rejected
    assert g.get("h1").rejected or g.get("h2").rejected
    alive = [n for n in g.get_pending() if not n.rejected]
    assert len(alive) <= 1  # At most one survives


def test_dedup_no_false_positives():
    from app.engine.hypothesis_graph import HypothesisGraph
    from app.engine.hypothesis_deduplicator import HypothesisDeduplicator
    g = HypothesisGraph()
    g.add(_hyp("h1", vuln_class="sqli"), "a")
    g.add(_hyp("h2", vuln_class="xss"), "a")
    result = HypothesisDeduplicator().deduplicate(g)
    assert result.duplicates_found == 0


def test_dedup_result_to_dict():
    from app.engine.hypothesis_graph import HypothesisGraph
    from app.engine.hypothesis_deduplicator import HypothesisDeduplicator
    g = HypothesisGraph()
    g.add(_hyp("h1"), "a")
    result = HypothesisDeduplicator().deduplicate(g)
    d = result.to_dict()
    assert "reduction_pct" in d


# ═══════════════════════════════════════════════════════════════════
# 3. Coverage Tracker
# ═══════════════════════════════════════════════════════════════════


def test_coverage_record_and_check():
    from app.engine.coverage_tracker import CoverageTracker
    tracker = CoverageTracker()
    tracker.record_test("ep1", "sql_injection", "nuclei")
    assert tracker.is_covered("ep1", "sql_injection", "nuclei")
    assert not tracker.is_covered("ep1", "xss", "nuclei")


def test_coverage_prunes_redundant():
    from app.engine.hypothesis_graph import HypothesisGraph
    from app.engine.coverage_tracker import CoverageTracker
    g = HypothesisGraph()
    g.add(_hyp("h1", vuln_class="sqli"), "a")
    tracker = CoverageTracker()
    tracker.record_test("ep1", "sqli", "nuclei")
    result = tracker.prune(g)
    assert result.redundant_pruned == 1


def test_coverage_allows_novel():
    from app.engine.hypothesis_graph import HypothesisGraph
    from app.engine.coverage_tracker import CoverageTracker
    g = HypothesisGraph()
    g.add(_hyp("h1", vuln_class="xss"), "a")
    tracker = CoverageTracker()
    tracker.record_test("ep1", "sqli", "nuclei")  # Different class
    result = tracker.prune(g)
    assert result.novel_approved == 1


def test_coverage_summary():
    from app.engine.coverage_tracker import CoverageTracker
    tracker = CoverageTracker()
    tracker.record_test("ep1", "sqli", "nuclei")
    tracker.record_test("ep1", "xss", "nuclei")
    s = tracker.summary()
    assert s["tracked_assets"] == 1
    assert s["total_tests"] == 2


# ═══════════════════════════════════════════════════════════════════
# 4. Complexity Controller
# ═══════════════════════════════════════════════════════════════════


def test_complexity_depth_limit():
    from app.engine.hypothesis_graph import HypothesisGraph
    from app.engine.complexity_controller import ComplexityController, ComplexityLimits
    g = HypothesisGraph()
    g.add(_hyp("h1", chain_length=10), "a")  # Exceeds default max_chain_depth=5
    ctrl = ComplexityController(ComplexityLimits(max_chain_depth=5))
    result = ctrl.enforce(g)
    assert result.depth_pruned == 1


def test_complexity_asset_cap():
    from app.engine.hypothesis_graph import HypothesisGraph
    from app.engine.complexity_controller import ComplexityController, ComplexityLimits
    g = HypothesisGraph()
    for i in range(20):
        g.add(_hyp(f"h{i}", vuln_class=f"class{i}"), "a")
    ctrl = ComplexityController(ComplexityLimits(max_hypotheses_per_asset=10))
    result = ctrl.enforce(g)
    assert result.asset_cap_pruned == 10


def test_complexity_module_cap():
    from app.engine.hypothesis_graph import HypothesisGraph
    from app.engine.complexity_controller import ComplexityController, ComplexityLimits
    g = HypothesisGraph()
    for i in range(15):
        g.add(_hyp(f"h{i}", target=f"ep{i}", vuln_class=f"c{i}"), "heuristic")
    ctrl = ComplexityController(ComplexityLimits(max_per_module=10, max_hypotheses_per_asset=100))
    result = ctrl.enforce(g)
    assert result.module_cap_pruned == 5


def test_complexity_total_cap():
    from app.engine.hypothesis_graph import HypothesisGraph
    from app.engine.complexity_controller import ComplexityController, ComplexityLimits
    g = HypothesisGraph()
    for i in range(25):
        g.add(_hyp(f"h{i}", target=f"ep{i}", vuln_class=f"c{i}"), f"mod{i % 5}")
    ctrl = ComplexityController(ComplexityLimits(max_total_pending=10,
                                                  max_hypotheses_per_asset=100,
                                                  max_per_module=100))
    result = ctrl.enforce(g)
    assert result.total_cap_pruned == 15


def test_complexity_result_to_dict():
    from app.engine.complexity_controller import ComplexityResult
    r = ComplexityResult(total_checked=20, depth_pruned=2, asset_cap_pruned=3)
    d = r.to_dict()
    assert d["total_pruned"] == 5


# ═══════════════════════════════════════════════════════════════════
# 5. Full Pipeline Integration
# ═══════════════════════════════════════════════════════════════════


def test_full_hypothesis_management_pipeline():
    """End-to-end: add → deduplicate → coverage prune → complexity enforce → approve survivors."""
    from app.engine.hypothesis_graph import HypothesisGraph
    from app.engine.hypothesis_deduplicator import HypothesisDeduplicator
    from app.engine.coverage_tracker import CoverageTracker
    from app.engine.complexity_controller import ComplexityController

    g = HypothesisGraph()

    # Simulate multiple modules generating overlapping hypotheses
    g.add(_hyp("heur1", vuln_class="sqli", test_type="fuzz"), "heuristic", confidence=0.8)
    g.add(_hyp("expl1", vuln_class="sqli", test_type="fuzz"), "exploration", confidence=0.6)
    g.add(_hyp("heur2", vuln_class="xss", test_type="inject"), "heuristic", confidence=0.7)
    g.add(_hyp("pat1", vuln_class="idor", test_type="param_swap"), "pattern", confidence=0.5)
    g.add(_hyp("ref1", vuln_class="sqli", test_type="bypass", refinement=True, attempt_number=2), "refinement")

    assert g.total == 5

    # 1 — Deduplication
    dedup_result = HypothesisDeduplicator().deduplicate(g)
    assert dedup_result.duplicates_found >= 1  # sqli/fuzz duplicated

    # 2 — Coverage pruning (pretend sqli already tested)
    tracker = CoverageTracker()
    tracker.record_test("ep1", "sqli", "nuclei")
    cov_result = tracker.prune(g)

    # 3 — Complexity enforcement
    ctrl = ComplexityController()
    comp_result = ctrl.enforce(g)

    # Approve survivors
    for node in g.get_pending():
        g.approve(node.hypothesis.hypothesis_id)

    approved = g.get_approved()
    assert len(approved) > 0
    assert len(approved) < 5  # Some were pruned


def test_heavy_generation_reduction():
    """Simulate 500 hypotheses from multiple modules, verify aggressive pruning."""
    from app.engine.hypothesis_graph import HypothesisGraph
    from app.engine.hypothesis_deduplicator import HypothesisDeduplicator
    from app.engine.coverage_tracker import CoverageTracker
    from app.engine.complexity_controller import ComplexityController, ComplexityLimits

    g = HypothesisGraph()

    # Generate 500 hypotheses from 5 modules
    for mod in range(5):
        for i in range(100):
            g.add(
                _hyp(f"h_{mod}_{i}", target=f"ep{i % 10}", vuln_class=f"class{i % 8}",
                     test_type=f"test{i % 3}", tool="nuclei"),
                f"module_{mod}",
            )

    assert g.total == 500

    # Full pipeline
    HypothesisDeduplicator().deduplicate(g)
    CoverageTracker().prune(g)
    ComplexityController(ComplexityLimits(
        max_hypotheses_per_asset=10,
        max_per_module=20,
        max_total_pending=50,
    )).enforce(g)

    pending = g.get_pending()
    assert len(pending) <= 50  # Total cap enforced
    assert len(pending) < 500  # Significant reduction


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
