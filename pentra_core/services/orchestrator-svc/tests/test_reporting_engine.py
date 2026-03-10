"""MOD-14 Reporting Engine tests — validates narrative, evidence, risk,
compliance, and report generation.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_reporting_engine.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def _sample_path():
    return [
        {"type": "entrypoint", "label": "example.com"},
        {"type": "endpoint", "label": "/admin", "technique": "directory_brute"},
        {"type": "vulnerability", "label": "/admin/login", "technique": "sql_injection"},
        {"type": "credential", "label": "admin:pass123"},
        {"type": "privilege", "label": "root shell", "technique": "sudo_bypass"},
    ]


def _sample_findings():
    return [
        {
            "id": "v1", "vulnerability_type": "sqli", "target": "/admin/login",
            "cvss": 9.0, "verified": True,
            "request": "GET /admin/login' OR 1=1--",
            "response": "HTTP/1.1 200 OK\nWelcome admin",
            "payload": "' OR 1=1--",
            "exploit_result": "Authentication bypassed",
        },
        {
            "id": "v2", "vulnerability_type": "xss", "target": "/search",
            "cvss": 6.5,
            "request": "GET /search?q=<script>alert(1)</script>",
            "response": "HTTP/1.1 200 OK\n<script>alert(1)</script>",
            "payload": "<script>alert(1)</script>",
        },
        {
            "id": "v3", "vulnerability_type": "idor", "target": "/api/users/42",
            "cvss": 7.5, "verified": True,
            "request": "GET /api/users/42",
            "response": "HTTP/1.1 200 OK\n{\"email\": \"admin@example.com\"}",
            "exploit_result": "User data exposed",
        },
    ]


# ═══════════════════════════════════════════════════════════════════
# 1. Attack Narrative
# ═══════════════════════════════════════════════════════════════════


def test_narrative_generates():
    from app.engine.attack_narrative import AttackNarrativeGenerator
    nar = AttackNarrativeGenerator().generate("scan-001", _sample_path())
    assert len(nar.steps) == 5
    assert "critical" in nar.summary


def test_narrative_action_types():
    from app.engine.attack_narrative import AttackNarrativeGenerator
    nar = AttackNarrativeGenerator().generate("scan-001", _sample_path())
    actions = {s.action for s in nar.steps}
    assert "discovery" in actions
    assert "exploitation" in actions
    assert "credential_extraction" in actions


def test_narrative_recommendations():
    from app.engine.attack_narrative import AttackNarrativeGenerator
    nar = AttackNarrativeGenerator().generate("scan-001", _sample_path())
    assert len(nar.recommendations) >= 2


def test_narrative_to_dict():
    from app.engine.attack_narrative import AttackNarrativeGenerator
    d = AttackNarrativeGenerator().generate("scan-001", _sample_path()).to_dict()
    assert "steps" in d
    assert "impact" in d


def test_narrative_to_markdown():
    from app.engine.attack_narrative import AttackNarrativeGenerator
    md = AttackNarrativeGenerator().generate("scan-001", _sample_path()).to_markdown()
    assert "Attack Path" in md
    assert "Step 1" in md


# ═══════════════════════════════════════════════════════════════════
# 2. Evidence Extractor
# ═══════════════════════════════════════════════════════════════════


def test_evidence_extracts():
    from app.engine.evidence_extractor import EvidenceExtractor
    evidence = EvidenceExtractor().extract(_sample_findings())
    assert len(evidence) >= 6  # 3 findings × 2+ evidence types each


def test_evidence_types():
    from app.engine.evidence_extractor import EvidenceExtractor
    evidence = EvidenceExtractor().extract(_sample_findings())
    types = {e.evidence_type for e in evidence}
    assert "request" in types
    assert "payload" in types


def test_evidence_sorted_by_severity():
    from app.engine.evidence_extractor import EvidenceExtractor
    evidence = EvidenceExtractor().extract(_sample_findings())
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    orders = [severity_order.get(e.severity, 5) for e in evidence]
    assert orders == sorted(orders)


def test_evidence_group_by_target():
    from app.engine.evidence_extractor import EvidenceExtractor
    ext = EvidenceExtractor()
    evidence = ext.extract(_sample_findings())
    groups = ext.group_by_target(evidence)
    assert len(groups) >= 2


def test_evidence_to_markdown():
    from app.engine.evidence_extractor import EvidenceExtractor
    evidence = EvidenceExtractor().extract(_sample_findings())
    md = evidence[0].to_markdown()
    assert "Evidence" in md


# ═══════════════════════════════════════════════════════════════════
# 3. Risk Prioritizer
# ═══════════════════════════════════════════════════════════════════


def test_risk_prioritizes():
    from app.engine.risk_prioritizer import RiskPrioritizer
    ranked = RiskPrioritizer().prioritize(_sample_findings())
    assert len(ranked) == 3


def test_risk_sorted_by_score():
    from app.engine.risk_prioritizer import RiskPrioritizer
    ranked = RiskPrioritizer().prioritize(_sample_findings())
    scores = [r.risk_score for r in ranked]
    assert scores == sorted(scores, reverse=True)


def test_risk_verified_higher():
    from app.engine.risk_prioritizer import RiskPrioritizer
    ranked = RiskPrioritizer().prioritize(_sample_findings())
    sqli = next(r for r in ranked if "sqli" in r.title.lower() or "sqli" in r.vuln_id)
    xss = next(r for r in ranked if "xss" in r.title.lower() or "xss" in r.vuln_id)
    assert sqli.risk_score > xss.risk_score


def test_risk_remediation():
    from app.engine.risk_prioritizer import RiskPrioritizer
    ranked = RiskPrioritizer().prioritize(_sample_findings())
    sqli = next(r for r in ranked if "sqli" in r.title.lower() or "sqli" in r.vuln_id)
    assert "parameterized" in sqli.remediation.lower()


def test_risk_top():
    from app.engine.risk_prioritizer import RiskPrioritizer
    top = RiskPrioritizer().top_risks(_sample_findings(), n=2)
    assert len(top) == 2


def test_risk_summary():
    from app.engine.risk_prioritizer import RiskPrioritizer
    ranked = RiskPrioritizer().prioritize(_sample_findings())
    s = RiskPrioritizer().summary(ranked)
    assert s["total"] == 3


# ═══════════════════════════════════════════════════════════════════
# 4. Compliance Mapper
# ═══════════════════════════════════════════════════════════════════


def test_compliance_maps_owasp():
    from app.engine.compliance_mapper import ComplianceMapper
    m = ComplianceMapper().map_finding("sqli")
    assert len(m.owasp) >= 1
    assert "Injection" in m.owasp[0]


def test_compliance_maps_mitre():
    from app.engine.compliance_mapper import ComplianceMapper
    m = ComplianceMapper().map_finding("rce")
    assert len(m.mitre) >= 1


def test_compliance_maps_cwe():
    from app.engine.compliance_mapper import ComplianceMapper
    m = ComplianceMapper().map_finding("xss")
    assert "CWE-79" in m.cwe


def test_compliance_batch():
    from app.engine.compliance_mapper import ComplianceMapper
    mappings = ComplianceMapper().map_findings(_sample_findings())
    assert len(mappings) == 3


def test_compliance_coverage():
    from app.engine.compliance_mapper import ComplianceMapper
    mapper = ComplianceMapper()
    mappings = mapper.map_findings(_sample_findings())
    cov = mapper.coverage_summary(mappings)
    assert cov["owasp_categories"] >= 2


# ═══════════════════════════════════════════════════════════════════
# 5. Report Generator
# ═══════════════════════════════════════════════════════════════════


def test_report_generates():
    from app.engine.report_generator import ReportGenerator
    report = ReportGenerator().generate("scan-001", _sample_findings(), _sample_path())
    assert report.report_id.startswith("report:")
    assert len(report.vulnerabilities) >= 3


def test_report_executive_summary():
    from app.engine.report_generator import ReportGenerator
    report = ReportGenerator().generate("scan-001", _sample_findings(), _sample_path())
    assert "scan-001" in report.executive_summary
    assert "vulnerabilities" in report.executive_summary


def test_report_to_json():
    from app.engine.report_generator import ReportGenerator
    report = ReportGenerator().generate("scan-001", _sample_findings(), _sample_path())
    j = report.to_json()
    assert '"report_id"' in j
    assert '"vulnerabilities"' in j


def test_report_to_markdown():
    from app.engine.report_generator import ReportGenerator
    report = ReportGenerator().generate("scan-001", _sample_findings(), _sample_path())
    md = report.to_markdown()
    assert "Executive Summary" in md
    assert "Vulnerabilities" in md
    assert "Compliance" in md


def test_report_without_path():
    from app.engine.report_generator import ReportGenerator
    report = ReportGenerator().generate("scan-002", _sample_findings())
    assert report.narrative is None
    assert len(report.vulnerabilities) >= 3


# ═══════════════════════════════════════════════════════════════════
# 6. Full Pipeline
# ═══════════════════════════════════════════════════════════════════


def test_full_reporting_pipeline():
    """End-to-end: attack path + findings → complete report."""
    from app.engine.report_generator import ReportGenerator

    report = ReportGenerator().generate("scan-full", _sample_findings(), _sample_path())

    # Narrative
    assert report.narrative is not None
    assert len(report.narrative.steps) == 5

    # Vulns ranked
    assert len(report.vulnerabilities) >= 3
    assert report.vulnerabilities[0].risk_score >= report.vulnerabilities[-1].risk_score

    # Evidence
    assert len(report.evidence) >= 6

    # Compliance
    assert len(report.compliance) == 3

    # Exports
    assert len(report.to_json()) > 100
    assert "Executive Summary" in report.to_markdown()


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
