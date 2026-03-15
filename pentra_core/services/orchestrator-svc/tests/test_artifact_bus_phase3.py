from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_merge_finding_record_prefers_stronger_source_and_dedupes_references():
    from app.engine.artifact_bus import _merge_finding_record

    existing = {
        "source_type": "scanner",
        "severity": "high",
        "confidence": 82,
        "title": "SQL Injection in Login Endpoint",
        "cve_id": None,
        "cvss_score": 8.5,
        "description": "Initial detection",
        "remediation": "Use prepared statements.",
        "tool_source": "nuclei",
        "evidence": {
            "storage_ref": "artifacts/scan/nuclei.json",
            "references": [
                {
                    "id": "req-1",
                    "evidence_type": "request",
                    "content_preview": "POST /api/v1/auth/login",
                    "storage_ref": "artifacts/scan/nuclei.json#req-1",
                }
            ],
            "classification": {"exploitability": "medium"},
        },
    }
    candidate = {
        "source_type": "ai_analysis",
        "severity": "critical",
        "confidence": 96,
        "title": "SQL Injection in Login Endpoint",
        "cve_id": None,
        "cvss_score": 9.8,
        "description": "Merged exploit path confirms auth bypass and likely data exposure.",
        "remediation": "Replace string interpolation with parameterized queries.",
        "tool_source": "ai_triage",
        "evidence": {
            "storage_ref": "artifacts/scan/ai_triage.json",
            "references": [
                {
                    "id": "req-1",
                    "evidence_type": "request",
                    "content_preview": "POST /api/v1/auth/login",
                    "storage_ref": "artifacts/scan/nuclei.json#req-1",
                }
            ],
            "classification": {"exploitability": "high"},
        },
    }

    merged = _merge_finding_record(existing=existing, candidate=candidate)

    assert merged["source_type"] == "ai_analysis"
    assert merged["severity"] == "critical"
    assert merged["confidence"] == 96
    assert len(merged["evidence"]["references"]) == 1
    assert merged["evidence"]["classification"]["exploitability"] == "high"
    assert merged["evidence"]["metadata"]["tool_sources"] == ["ai_triage", "nuclei"]
