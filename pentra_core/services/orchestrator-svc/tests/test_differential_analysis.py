"""MOD-13.5 Differential Analysis Engine tests — validates response collector,
normalizer, differential analyzer, anomaly detector, and full pipeline.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_differential_analysis.py -v
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
# 1. Response Collector
# ═══════════════════════════════════════════════════════════════════


def test_collector_collects():
    from app.engine.response_collector import ResponseCollector
    c = ResponseCollector()
    rec = c.collect("/api/users", body="hello", status_code=200)
    assert c.total == 1
    assert rec.body_hash != ""


def test_collector_indexes_by_endpoint():
    from app.engine.response_collector import ResponseCollector
    c = ResponseCollector()
    c.collect("/api/users", body="a")
    c.collect("/api/users", body="b")
    c.collect("/api/items", body="c")
    assert len(c.get_by_endpoint("/api/users")) == 2
    assert len(c.get_by_endpoint("/api/items")) == 1


def test_collector_get_by_status():
    from app.engine.response_collector import ResponseCollector
    c = ResponseCollector()
    c.collect("/a", status_code=200)
    c.collect("/b", status_code=500)
    assert len(c.get_by_status(500)) == 1


def test_collector_endpoints():
    from app.engine.response_collector import ResponseCollector
    c = ResponseCollector()
    c.collect("/a")
    c.collect("/b")
    assert set(c.get_endpoints()) == {"/a", "/b"}


def test_collector_summary():
    from app.engine.response_collector import ResponseCollector
    c = ResponseCollector()
    c.collect("/a")
    s = c.summary()
    assert s["total"] == 1


def test_collector_to_dict():
    from app.engine.response_collector import ResponseCollector
    c = ResponseCollector()
    rec = c.collect("/a", body="test", elapsed_ms=150.0)
    d = rec.to_dict()
    assert d["endpoint"] == "/a"


# ═══════════════════════════════════════════════════════════════════
# 2. Response Normalizer
# ═══════════════════════════════════════════════════════════════════


def test_normalizer_removes_timestamps():
    from app.engine.response_collector import ResponseRecord
    from app.engine.response_normalizer import ResponseNormalizer
    rec = ResponseRecord("r1", "/api", body="created_at: 2024-01-15T10:30:45Z")
    norm = ResponseNormalizer().normalize(rec)
    assert "2024-01-15" not in norm.normalized_body
    assert "timestamp" in norm.noise_removed


def test_normalizer_removes_uuids():
    from app.engine.response_collector import ResponseRecord
    from app.engine.response_normalizer import ResponseNormalizer
    rec = ResponseRecord("r1", "/api", body='id: "550e8400-e29b-41d4-a716-446655440000"')
    norm = ResponseNormalizer().normalize(rec)
    assert "550e8400" not in norm.normalized_body


def test_normalizer_removes_jwts():
    from app.engine.response_collector import ResponseRecord
    from app.engine.response_normalizer import ResponseNormalizer
    rec = ResponseRecord("r1", "/api", body="token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkw.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
    norm = ResponseNormalizer().normalize(rec)
    assert "eyJ" not in norm.normalized_body


def test_normalizer_batch():
    from app.engine.response_collector import ResponseRecord
    from app.engine.response_normalizer import ResponseNormalizer
    recs = [
        ResponseRecord("r1", "/a", body="ts: 2024-01-01T00:00:00Z"),
        ResponseRecord("r2", "/b", body="stable content"),
    ]
    norms = ResponseNormalizer().normalize_batch(recs)
    assert len(norms) == 2


def test_normalizer_produces_hash():
    from app.engine.response_collector import ResponseRecord
    from app.engine.response_normalizer import ResponseNormalizer
    rec = ResponseRecord("r1", "/api", body="stable content")
    norm = ResponseNormalizer().normalize(rec)
    assert len(norm.normalized_hash) == 12


def test_normalizer_filter_headers():
    from app.engine.response_normalizer import ResponseNormalizer
    headers = {"Content-Type": "json", "Set-Cookie": "abc", "Date": "now", "X-Custom": "val"}
    filtered = ResponseNormalizer().filter_headers(headers)
    assert "Content-Type" in filtered
    assert "Set-Cookie" not in filtered


# ═══════════════════════════════════════════════════════════════════
# 3. Differential Analyzer
# ═══════════════════════════════════════════════════════════════════


def _make_norm(rid, endpoint="/api", status=200, body="ok", length=None, elapsed=100.0):
    from app.engine.response_normalizer import NormalizedResponse
    import hashlib
    h = hashlib.md5(body.encode()).hexdigest()[:12]
    return NormalizedResponse(
        original_id=rid, endpoint=endpoint, status_code=status,
        normalized_body=body, normalized_hash=h,
        body_length=length or len(body), elapsed_ms=elapsed,
    )


def test_analyzer_detects_status_diff():
    from app.engine.differential_analyzer import DifferentialAnalyzer
    baseline = [_make_norm(f"b{i}", status=200) for i in range(5)]
    test = [_make_norm("t1", status=403)]
    result = DifferentialAnalyzer().analyze(baseline, test)
    types = {d.diff_type for d in result.differentials}
    assert "status_diff" in types


def test_analyzer_detects_size_diff():
    from app.engine.differential_analyzer import DifferentialAnalyzer
    baseline = [_make_norm(f"b{i}", body="short", length=5) for i in range(5)]
    test = [_make_norm("t1", body="very long response " * 100, length=2000)]
    result = DifferentialAnalyzer().analyze(baseline, test)
    types = {d.diff_type for d in result.differentials}
    assert "size_diff" in types


def test_analyzer_detects_timing_diff():
    from app.engine.differential_analyzer import DifferentialAnalyzer
    baseline = [_make_norm(f"b{i}", elapsed=100.0) for i in range(5)]
    test = [_make_norm("t1", elapsed=5000.0)]
    result = DifferentialAnalyzer().analyze(baseline, test)
    types = {d.diff_type for d in result.differentials}
    assert "timing_diff" in types


def test_analyzer_detects_error_diff():
    from app.engine.differential_analyzer import DifferentialAnalyzer
    baseline = [_make_norm(f"b{i}", status=200) for i in range(5)]
    test = [_make_norm("t1", status=500)]
    result = DifferentialAnalyzer().analyze(baseline, test)
    types = {d.diff_type for d in result.differentials}
    assert "error_diff" in types


def test_analyzer_no_false_positives():
    from app.engine.differential_analyzer import DifferentialAnalyzer
    baseline = [_make_norm(f"b{i}") for i in range(5)]
    test = [_make_norm("t1")]
    result = DifferentialAnalyzer().analyze(baseline, test)
    assert result.anomaly_count == 0


def test_analyzer_within():
    from app.engine.differential_analyzer import DifferentialAnalyzer
    responses = [_make_norm(f"r{i}") for i in range(4)] + [_make_norm("bad", status=500)]
    result = DifferentialAnalyzer().analyze_within(responses)
    assert result.total_compared >= 1


def test_analyzer_result_to_dict():
    from app.engine.differential_analyzer import DifferentialAnalyzer
    baseline = [_make_norm(f"b{i}") for i in range(3)]
    test = [_make_norm("t1", status=403)]
    result = DifferentialAnalyzer().analyze(baseline, test)
    d = result.to_dict()
    assert "anomalies" in d


# ═══════════════════════════════════════════════════════════════════
# 4. Anomaly Detector
# ═══════════════════════════════════════════════════════════════════


def test_detector_creates_anomalies():
    from app.engine.differential_analyzer import DifferentialAnalyzer
    from app.engine.anomaly_detector import AnomalyDetector
    baseline = [_make_norm(f"b{i}") for i in range(5)]
    test = [_make_norm("t1", status=403)]
    diff_result = DifferentialAnalyzer().analyze(baseline, test)
    anomalies = AnomalyDetector().detect(diff_result)
    assert len(anomalies) > 0


def test_detector_anomaly_types():
    from app.engine.differential_analyzer import DifferentialAnalyzer
    from app.engine.anomaly_detector import AnomalyDetector
    baseline = [_make_norm(f"b{i}") for i in range(5)]
    test = [_make_norm("t1", status=500, elapsed=5000.0)]
    diff_result = DifferentialAnalyzer().analyze(baseline, test)
    anomalies = AnomalyDetector().detect(diff_result)
    types = {a.anomaly_type for a in anomalies}
    assert len(types) >= 2


def test_detector_to_hypotheses():
    from app.engine.differential_analyzer import DifferentialAnalyzer
    from app.engine.anomaly_detector import AnomalyDetector
    baseline = [_make_norm(f"b{i}") for i in range(5)]
    test = [_make_norm("t1", status=403)]
    diff_result = DifferentialAnalyzer().analyze(baseline, test)
    anomalies = AnomalyDetector().detect(diff_result)
    hyps = AnomalyDetector().to_hypotheses(anomalies)
    assert len(hyps) == len(anomalies)
    for h in hyps:
        assert h.hypothesis_id.startswith("diff_hyp:")


def test_detector_sorted_by_confidence():
    from app.engine.differential_analyzer import DifferentialAnalyzer
    from app.engine.anomaly_detector import AnomalyDetector
    baseline = [_make_norm(f"b{i}") for i in range(5)]
    test = [_make_norm("t1", status=500, elapsed=5000.0)]
    diff_result = DifferentialAnalyzer().analyze(baseline, test)
    anomalies = AnomalyDetector().detect(diff_result)
    confs = [a.confidence for a in anomalies]
    assert confs == sorted(confs, reverse=True)


def test_detector_summary():
    from app.engine.differential_analyzer import DifferentialAnalyzer
    from app.engine.anomaly_detector import AnomalyDetector
    baseline = [_make_norm(f"b{i}") for i in range(5)]
    test = [_make_norm("t1", status=403)]
    diff_result = DifferentialAnalyzer().analyze(baseline, test)
    anomalies = AnomalyDetector().detect(diff_result)
    s = AnomalyDetector().summary(anomalies)
    assert "total" in s


# ═══════════════════════════════════════════════════════════════════
# 5. Full Pipeline Integration
# ═══════════════════════════════════════════════════════════════════


def test_full_differential_pipeline():
    """End-to-end: collect → normalize → diff → detect → hypotheses."""
    from app.engine.response_collector import ResponseCollector
    from app.engine.response_normalizer import ResponseNormalizer
    from app.engine.differential_analyzer import DifferentialAnalyzer
    from app.engine.anomaly_detector import AnomalyDetector

    # 1 — Collect responses
    collector = ResponseCollector()
    for i in range(5):
        collector.collect("/api/users", body=f"user list ts=2024-01-01T00:00:0{i}Z",
                          status_code=200, elapsed_ms=100.0)
    collector.collect("/api/users", body="forbidden", status_code=403, elapsed_ms=4000.0)

    # 2 — Normalize
    normalizer = ResponseNormalizer()
    all_records = collector.get_by_endpoint("/api/users")
    normals = normalizer.normalize_batch(all_records)
    assert len(normals) == 6

    # 3 — Differential analysis
    baseline = normals[:5]
    test = normals[5:]
    diff_result = DifferentialAnalyzer().analyze(baseline, test)
    assert diff_result.anomaly_count > 0

    # 4 — Anomaly detection → hypotheses
    anomalies = AnomalyDetector().detect(diff_result)
    hyps = AnomalyDetector().to_hypotheses(anomalies)
    assert len(hyps) > 0


def test_differential_with_hypothesis_graph():
    """Verify differential hypotheses integrate into the Hypothesis Graph."""
    from app.engine.differential_analyzer import DifferentialAnalyzer
    from app.engine.anomaly_detector import AnomalyDetector
    from app.engine.hypothesis_graph import HypothesisGraph

    baseline = [_make_norm(f"b{i}") for i in range(5)]
    test = [_make_norm("t1", status=500)]

    diff_result = DifferentialAnalyzer().analyze(baseline, test)
    anomalies = AnomalyDetector().detect(diff_result)
    hyps = AnomalyDetector().to_hypotheses(anomalies)

    graph = HypothesisGraph()
    graph.add_batch(hyps, "differential")
    assert graph.total == len(hyps)
    assert len(graph.get_by_module("differential")) == len(hyps)


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
