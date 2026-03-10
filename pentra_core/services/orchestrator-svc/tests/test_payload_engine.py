"""MOD-11.5 Offensive Payload Intelligence Engine tests — validates payload
knowledge base, mutator, evaluator, and pipeline integration.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_payload_engine.py -v
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
# 1. Payload Knowledge Base
# ═══════════════════════════════════════════════════════════════════


def test_payload_classes_loaded():
    from app.engine.payload_mutator import PayloadMutator
    m = PayloadMutator()
    assert len(m.payload_classes) >= 6


def test_sql_injection_payloads_exist():
    from app.engine.payload_mutator import PayloadMutator
    m = PayloadMutator()
    base = m.get_base_payloads("sql_injection")
    assert len(base) >= 10


def test_command_injection_payloads_exist():
    from app.engine.payload_mutator import PayloadMutator
    m = PayloadMutator()
    base = m.get_base_payloads("command_injection")
    assert len(base) >= 10


def test_all_classes_have_payloads():
    from app.engine.payload_mutator import PayloadMutator
    m = PayloadMutator()
    for cls in m.payload_classes:
        assert len(m.get_base_payloads(cls)) > 0, f"No payloads for {cls}"


# ═══════════════════════════════════════════════════════════════════
# 2. Payload Mutator
# ═══════════════════════════════════════════════════════════════════


def test_mutator_generates_variants():
    from app.engine.payload_mutator import PayloadMutator
    m = PayloadMutator()
    variants = m.generate("sql_injection", max_variants=20)
    assert len(variants) > 0
    assert len(variants) <= 20


def test_mutator_includes_base_payloads():
    from app.engine.payload_mutator import PayloadMutator
    m = PayloadMutator()
    variants = m.generate("sql_injection", max_variants=50)
    base = [v for v in variants if v.mutation_applied == "none"]
    assert len(base) > 0


def test_mutator_applies_mutations():
    from app.engine.payload_mutator import PayloadMutator
    m = PayloadMutator()
    variants = m.generate("sql_injection", max_variants=50)
    mutated = [v for v in variants if v.mutation_applied != "none" and not v.mutation_applied.startswith("encode:")]
    assert len(mutated) > 0


def test_mutator_applies_encodings():
    from app.engine.payload_mutator import PayloadMutator
    m = PayloadMutator()
    variants = m.generate("sql_injection", max_variants=100)
    encoded = [v for v in variants if v.mutation_applied.startswith("encode:")]
    assert len(encoded) > 0


def test_mutator_case_variation():
    from app.engine.payload_mutator import PayloadMutator
    m = PayloadMutator()
    variants = m.generate("sql_injection", max_variants=50)
    case_mutated = [v for v in variants if v.mutation_applied == "case_variation"]
    assert len(case_mutated) > 0
    for v in case_mutated:
        assert v.mutated != v.original


def test_mutator_url_encoding():
    from app.engine.payload_mutator import PayloadMutator
    m = PayloadMutator()
    variants = m.generate("sql_injection", max_variants=100)
    url_enc = [v for v in variants if v.mutation_applied == "encode:url"]
    assert len(url_enc) > 0
    for v in url_enc:
        assert "%" in v.mutated


def test_mutator_command_injection():
    from app.engine.payload_mutator import PayloadMutator
    m = PayloadMutator()
    variants = m.generate("command_injection", max_variants=30)
    assert len(variants) > 0


def test_mutator_path_traversal():
    from app.engine.payload_mutator import PayloadMutator
    m = PayloadMutator()
    variants = m.generate("path_traversal", max_variants=30)
    assert len(variants) > 0


def test_mutator_respects_max():
    from app.engine.payload_mutator import PayloadMutator
    m = PayloadMutator()
    variants = m.generate("sql_injection", max_variants=5)
    assert len(variants) <= 5


def test_mutator_to_dict():
    from app.engine.payload_mutator import PayloadMutator
    m = PayloadMutator()
    variants = m.generate("sql_injection", max_variants=1)
    d = variants[0].to_dict()
    assert "original" in d
    assert "mutated" in d
    assert "class" in d


def test_mutator_unknown_class_returns_empty():
    from app.engine.payload_mutator import PayloadMutator
    m = PayloadMutator()
    assert m.generate("nonexistent") == []


# ═══════════════════════════════════════════════════════════════════
# 3. Payload Evaluator
# ═══════════════════════════════════════════════════════════════════


def test_evaluator_detects_sql_error():
    from app.engine.payload_evaluator import PayloadEvaluator
    e = PayloadEvaluator()
    result = e.evaluate(
        response={"status_code": 500, "body": "You have an error in your SQL syntax near '"},
        payload_class="sql_injection",
        payload="' OR 1=1--",
    )
    assert result.verdict in ("confirmed", "likely")
    assert len(result.indicators_found) > 0


def test_evaluator_detects_command_output():
    from app.engine.payload_evaluator import PayloadEvaluator
    e = PayloadEvaluator()
    result = e.evaluate(
        response={"status_code": 200, "body": "uid=1000(www-data) gid=1000(www-data)"},
        payload_class="command_injection",
        payload="; id",
    )
    assert result.verdict in ("confirmed", "likely")


def test_evaluator_detects_path_traversal():
    from app.engine.payload_evaluator import PayloadEvaluator
    e = PayloadEvaluator()
    result = e.evaluate(
        response={"status_code": 200, "body": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/sbin/nologin"},
        payload_class="path_traversal",
        payload="../../../etc/passwd",
    )
    assert result.verdict in ("confirmed", "likely")


def test_evaluator_detects_time_based_sqli():
    from app.engine.payload_evaluator import PayloadEvaluator
    e = PayloadEvaluator()
    result = e.evaluate(
        response={"status_code": 200, "body": "", "response_time_ms": 5200},
        payload_class="sql_injection",
        payload="' AND SLEEP(5)--",
    )
    assert "time_based_delay" in result.indicators_found


def test_evaluator_detects_content_length_anomaly():
    from app.engine.payload_evaluator import PayloadEvaluator
    e = PayloadEvaluator()
    result = e.evaluate(
        response={"status_code": 200, "body": "lots of data", "content_length": 5000, "baseline_content_length": 200},
        payload_class="sql_injection",
        payload="' UNION SELECT NULL--",
    )
    assert "content_length_anomaly" in result.indicators_found


def test_evaluator_negative_on_clean():
    from app.engine.payload_evaluator import PayloadEvaluator
    e = PayloadEvaluator()
    result = e.evaluate(
        response={"status_code": 403, "body": "Forbidden"},
        payload_class="sql_injection",
        payload="' OR 1=1--",
    )
    assert result.verdict == "negative"


def test_evaluator_template_injection():
    from app.engine.payload_evaluator import PayloadEvaluator
    e = PayloadEvaluator()
    result = e.evaluate(
        response={"status_code": 200, "body": "The result is 49 from the template"},
        payload_class="template_injection",
        payload="{{7*7}}",
    )
    assert result.verdict in ("confirmed", "likely")


def test_evaluator_batch():
    from app.engine.payload_evaluator import PayloadEvaluator
    e = PayloadEvaluator()
    results = e.evaluate_batch(
        [
            {"response": {"status_code": 500, "body": "SQL syntax error"}, "payload": "' OR 1=1--"},
            {"response": {"status_code": 200, "body": "OK"}, "payload": "test"},
        ],
        payload_class="sql_injection",
    )
    assert len(results) == 2


def test_evaluator_result_to_dict():
    from app.engine.payload_evaluator import PayloadEvaluator
    e = PayloadEvaluator()
    result = e.evaluate(
        response={"status_code": 200, "body": "ok"},
        payload_class="sql_injection",
        payload="test",
    )
    d = result.to_dict()
    assert "verdict" in d
    assert "payload_class" in d


# ═══════════════════════════════════════════════════════════════════
# 4. Full Pipeline
# ═══════════════════════════════════════════════════════════════════


def test_full_payload_pipeline():
    """End-to-end: generate → mutate → evaluate."""
    from app.engine.payload_mutator import PayloadMutator
    from app.engine.payload_evaluator import PayloadEvaluator

    mutator = PayloadMutator()
    evaluator = PayloadEvaluator()

    # Generate variants
    variants = mutator.generate("sql_injection", max_variants=10)
    assert len(variants) > 0

    # Simulate responses and evaluate
    for variant in variants[:3]:
        result = evaluator.evaluate(
            response={"status_code": 500, "body": "You have an error in your SQL syntax"},
            payload_class=variant.payload_class,
            payload=variant.mutated,
            mutation=variant.mutation_applied,
        )
        assert result.verdict in ("confirmed", "likely", "negative")


def test_full_multi_class_pipeline():
    """Test across all vulnerability classes."""
    from app.engine.payload_mutator import PayloadMutator
    from app.engine.payload_evaluator import PayloadEvaluator

    mutator = PayloadMutator()
    evaluator = PayloadEvaluator()

    for cls in mutator.payload_classes:
        variants = mutator.generate(cls, max_variants=5)
        assert len(variants) > 0
        for v in variants[:2]:
            result = evaluator.evaluate(
                response={"status_code": 200, "body": ""},
                payload_class=cls,
                payload=v.mutated,
                mutation=v.mutation_applied,
            )
            assert result.payload_class == cls


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
