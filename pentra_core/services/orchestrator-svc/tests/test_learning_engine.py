"""MOD-13 AI Offensive Learning Engine tests — validates learning store,
exploit learning, payload learning, chain learning, target clusterer,
and full pipeline integration.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_learning_engine.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)

from app.engine.learning_store import LearningStore, ExploitRecord, ChainRecord


def _populated_store() -> LearningStore:
    """Build a store with sample telemetry."""
    store = LearningStore()
    # Exploit records
    for i in range(10):
        store.record_exploit(ExploitRecord(
            record_id=f"e{i}", exploit_type="sqli", target=f"ep{i % 3}",
            tool="sqlmap", success=i % 3 != 0,  # ~66% success
        ))
    for i in range(5):
        store.record_exploit(ExploitRecord(
            record_id=f"x{i}", exploit_type="xss", target=f"ep{i}",
            tool="dalfox", success=i % 4 == 0,  # 25% success
        ))
    store.record_exploit(ExploitRecord(
        record_id="w1", exploit_type="sqli", target="ep0",
        tool="sqlmap", success=True, waf_bypassed=True,
        bypass_technique="chunked_encoding",
    ))
    # Chain records
    store.record_chain(ChainRecord(
        chain_id="c1", steps=["discovery", "sqli", "credential", "ssh"],
        target_tech="php_app", success=True,
    ))
    store.record_chain(ChainRecord(
        chain_id="c2", steps=["discovery", "sqli", "credential", "ssh"],
        target_tech="php_app", success=True,
    ))
    store.record_chain(ChainRecord(
        chain_id="c3", steps=["discovery", "xss", "session_hijack"],
        target_tech="react_spa", success=False,
    ))
    # Payload records
    store.record_payload("sqli", "union_based", True)
    store.record_payload("sqli", "union_based", True)
    store.record_payload("sqli", "union_based", False)
    store.record_payload("sqli", "blind_boolean", True)
    store.record_payload("sqli", "blind_boolean", False, false_positive=True)
    store.record_payload("xss", "reflected", True)
    store.record_payload("xss", "reflected", False)
    return store


# ═══════════════════════════════════════════════════════════════════
# 1. Learning Store
# ═══════════════════════════════════════════════════════════════════


def test_store_record_exploit():
    store = LearningStore()
    store.record_exploit(ExploitRecord("e1", "sqli", "ep1", "sqlmap", True))
    assert store.exploit_count == 1


def test_store_record_chain():
    store = LearningStore()
    store.record_chain(ChainRecord("c1", ["sqli", "cred"], "php", True))
    assert store.chain_count == 1


def test_store_exploit_stats():
    store = _populated_store()
    stats = store.get_exploit_stats("sqli")
    assert stats["total"] >= 10
    assert 0 < stats["success_rate"] < 1


def test_store_waf_bypasses():
    store = _populated_store()
    bypasses = store.get_waf_bypasses()
    assert len(bypasses) >= 1
    assert bypasses[0]["technique"] == "chunked_encoding"


def test_store_serialize():
    store = _populated_store()
    data = store.serialize()
    assert '"exploits"' in data
    assert '"chains"' in data


def test_store_summary():
    store = _populated_store()
    s = store.summary()
    assert s["exploits"] > 0
    assert s["chains"] > 0
    assert s["payloads"] > 0


# ═══════════════════════════════════════════════════════════════════
# 2. Exploit Learning
# ═══════════════════════════════════════════════════════════════════


def test_exploit_learning_scores():
    from app.engine.exploit_learning import ExploitLearning
    store = _populated_store()
    scores = ExploitLearning(store).compute_scores()
    assert len(scores) >= 2
    types = {s.exploit_type for s in scores}
    assert "sqli" in types


def test_exploit_learning_sorted():
    from app.engine.exploit_learning import ExploitLearning
    scores = ExploitLearning(_populated_store()).compute_scores()
    rates = [s.success_rate for s in scores]
    assert rates == sorted(rates, reverse=True)


def test_exploit_learning_recommended():
    from app.engine.exploit_learning import ExploitLearning
    best = ExploitLearning(_populated_store()).get_best_exploits()
    assert len(best) >= 1
    for s in best:
        assert s.recommended


def test_exploit_learning_get_score():
    from app.engine.exploit_learning import ExploitLearning
    score = ExploitLearning(_populated_store()).get_score("sqli")
    assert score is not None
    assert score.total_attempts >= 10


def test_exploit_learning_to_dict():
    from app.engine.exploit_learning import ExploitLearning
    scores = ExploitLearning(_populated_store()).compute_scores()
    d = scores[0].to_dict()
    assert "success_rate" in d


# ═══════════════════════════════════════════════════════════════════
# 3. Payload Learning
# ═══════════════════════════════════════════════════════════════════


def test_payload_learning_scores():
    from app.engine.payload_learning import PayloadLearning
    scores = PayloadLearning(_populated_store()).compute_scores()
    assert len(scores) >= 3


def test_payload_learning_effectiveness():
    from app.engine.payload_learning import PayloadLearning
    scores = PayloadLearning(_populated_store()).compute_scores()
    for s in scores:
        assert 0 <= s.effectiveness <= 1


def test_payload_learning_sorted():
    from app.engine.payload_learning import PayloadLearning
    scores = PayloadLearning(_populated_store()).compute_scores()
    effs = [s.effectiveness for s in scores]
    assert effs == sorted(effs, reverse=True)


def test_payload_learning_best_for_type():
    from app.engine.payload_learning import PayloadLearning
    best = PayloadLearning(_populated_store()).get_best_payloads("sqli")
    assert len(best) >= 1
    for s in best:
        assert s.payload_type == "sqli"


def test_payload_learning_to_dict():
    from app.engine.payload_learning import PayloadLearning
    scores = PayloadLearning(_populated_store()).compute_scores()
    d = scores[0].to_dict()
    assert "effectiveness" in d


# ═══════════════════════════════════════════════════════════════════
# 4. Chain Learning
# ═══════════════════════════════════════════════════════════════════


def test_chain_learning_patterns():
    from app.engine.chain_learning import ChainLearning
    patterns = ChainLearning(_populated_store()).compute_patterns()
    assert len(patterns) >= 2


def test_chain_learning_occurrences():
    from app.engine.chain_learning import ChainLearning
    patterns = ChainLearning(_populated_store()).compute_patterns()
    php_patterns = [p for p in patterns if p.target_tech == "php_app"]
    assert php_patterns[0].occurrences >= 2


def test_chain_learning_match_graph():
    from app.engine.chain_learning import ChainLearning
    matches = ChainLearning(_populated_store()).match_graph(
        ["discovery", "sqli", "credential", "ssh"]
    )
    assert len(matches) >= 1


def test_chain_learning_priority():
    from app.engine.chain_learning import ChainLearning
    patterns = ChainLearning(_populated_store()).compute_patterns()
    priorities = [p.priority for p in patterns]
    assert priorities == sorted(priorities, reverse=True)


def test_chain_learning_to_dict():
    from app.engine.chain_learning import ChainLearning
    patterns = ChainLearning(_populated_store()).compute_patterns()
    d = patterns[0].to_dict()
    assert "steps" in d
    assert "success_rate" in d


# ═══════════════════════════════════════════════════════════════════
# 5. Target Clusterer
# ═══════════════════════════════════════════════════════════════════


def test_clusterer_classify():
    from app.engine.target_clusterer import TargetClusterer
    clusterer = TargetClusterer(_populated_store())
    tech = clusterer.classify("target1", ["wordpress", "wp-admin", "php"])
    assert tech == "wordpress"


def test_clusterer_multiple_targets():
    from app.engine.target_clusterer import TargetClusterer
    clusterer = TargetClusterer(_populated_store())
    clusterer.classify("t1", ["wordpress", "wp-admin"])
    clusterer.classify("t2", ["wordpress", "wp-content"])
    clusterer.classify("t3", ["react", "next.js"])
    assert clusterer.cluster_count == 2


def test_clusterer_update_stats():
    from app.engine.target_clusterer import TargetClusterer
    clusterer = TargetClusterer(_populated_store())
    clusterer.classify("t1", ["wordpress", "wp-admin"])
    clusterer.update_stats("t1", "sqli", True)
    clusterer.update_stats("t1", "sqli", False)
    cluster = clusterer.get_cluster("wordpress")
    assert cluster.exploit_stats["sqli"]["total"] == 2
    assert cluster.exploit_stats["sqli"]["successes"] == 1


def test_clusterer_recommended_exploits():
    from app.engine.target_clusterer import TargetClusterer
    clusterer = TargetClusterer(_populated_store())
    clusterer.classify("t1", ["wordpress"])
    clusterer.update_stats("t1", "sqli", True)
    clusterer.update_stats("t1", "xss", False)
    recs = clusterer.get_recommended_exploits("t1")
    assert "sqli" in recs


def test_clusterer_to_dict():
    from app.engine.target_clusterer import TargetClusterer
    clusterer = TargetClusterer(_populated_store())
    clusterer.classify("t1", ["wordpress"])
    clusters = clusterer.get_clusters()
    d = clusters[0].to_dict()
    assert "tech" in d


def test_clusterer_summary():
    from app.engine.target_clusterer import TargetClusterer
    clusterer = TargetClusterer(_populated_store())
    clusterer.classify("t1", ["wordpress"])
    s = clusterer.summary()
    assert s["clusters"] == 1


# ═══════════════════════════════════════════════════════════════════
# 6. Full Pipeline Integration
# ═══════════════════════════════════════════════════════════════════


def test_full_learning_pipeline():
    """End-to-end: populate store → exploit scores → payload scores → chain patterns → target clusters."""
    from app.engine.exploit_learning import ExploitLearning
    from app.engine.payload_learning import PayloadLearning
    from app.engine.chain_learning import ChainLearning
    from app.engine.target_clusterer import TargetClusterer

    store = _populated_store()

    # Exploit learning
    exploit_scores = ExploitLearning(store).compute_scores()
    assert len(exploit_scores) >= 2
    sqli = next(s for s in exploit_scores if s.exploit_type == "sqli")
    assert sqli.success_rate > 0

    # Payload learning
    payload_scores = PayloadLearning(store).compute_scores()
    assert len(payload_scores) >= 3

    # Chain learning
    patterns = ChainLearning(store).compute_patterns()
    assert len(patterns) >= 2

    # Target clustering
    clusterer = TargetClusterer(store)
    clusterer.classify("ep0", ["php", "wordpress"])
    clusterer.update_stats("ep0", "sqli", True)
    recs = clusterer.get_recommended_exploits("ep0")
    assert len(recs) >= 1


def test_learning_influences_prioritization():
    """Verify learned scores can influence attack ordering."""
    from app.engine.exploit_learning import ExploitLearning

    store = _populated_store()
    scores = ExploitLearning(store).compute_scores()

    # sqli should rank higher than xss (66% vs 25%)
    sqli = next(s for s in scores if s.exploit_type == "sqli")
    xss = next(s for s in scores if s.exploit_type == "xss")
    assert sqli.success_rate > xss.success_rate


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
