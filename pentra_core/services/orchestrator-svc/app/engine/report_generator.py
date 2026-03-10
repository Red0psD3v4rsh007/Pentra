"""Report generator — generates structured pentest reports.

MOD-14: Assembles attack narratives, evidence, risk scores, and
compliance mappings into structured reports exportable as JSON
or Markdown.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.attack_narrative import AttackNarrative, AttackNarrativeGenerator
from app.engine.evidence_extractor import EvidenceExtractor, EvidenceItem
from app.engine.risk_prioritizer import RiskPrioritizer, RankedVulnerability
from app.engine.compliance_mapper import ComplianceMapper, ComplianceMapping

logger = logging.getLogger(__name__)


@dataclass
class PentestReport:
    """Complete pentest report."""

    report_id: str
    scan_id: str
    executive_summary: str
    narrative: AttackNarrative | None = None
    vulnerabilities: list[RankedVulnerability] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    compliance: list[ComplianceMapping] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "scan_id": self.scan_id,
            "executive_summary": self.executive_summary,
            "narrative": self.narrative.to_dict() if self.narrative else None,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "evidence_count": len(self.evidence),
            "compliance": [c.to_dict() for c in self.compliance],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_markdown(self) -> str:
        lines = [
            f"# Pentest Report — {self.scan_id}",
            "", "## Executive Summary", "", self.executive_summary, "",
        ]

        # Narrative
        if self.narrative:
            lines.append(self.narrative.to_markdown())
            lines.append("")

        # Vulnerabilities
        if self.vulnerabilities:
            lines.extend(["## Vulnerabilities", ""])
            lines.append("| # | Vulnerability | Target | Score | Severity |")
            lines.append("|---|---|---|---|---|")
            for i, v in enumerate(self.vulnerabilities, 1):
                lines.append(f"| {i} | {v.title} | {v.target} | {v.risk_score:.1f} | {v.severity} |")
            lines.append("")

        # Compliance
        if self.compliance:
            lines.extend(["## Compliance Mapping", ""])
            for cm in self.compliance:
                if cm.owasp or cm.cwe:
                    lines.append(f"- **{cm.vuln_type}**: {', '.join(cm.owasp + cm.cwe)}")
            lines.append("")

        # Evidence
        if self.evidence:
            lines.extend(["## Evidence", ""])
            for ev in self.evidence[:10]:
                lines.append(ev.to_markdown())
                lines.append("")

        return "\n".join(lines)


class ReportGenerator:
    """Generates complete pentest reports.

    Usage::

        gen = ReportGenerator()
        report = gen.generate(scan_id, findings, attack_path)
    """

    def __init__(self) -> None:
        self._narrative_gen = AttackNarrativeGenerator()
        self._evidence_ext = EvidenceExtractor()
        self._risk_pri = RiskPrioritizer()
        self._compliance = ComplianceMapper()
        self._counter = 0

    def generate(
        self,
        scan_id: str,
        findings: list[dict[str, Any]],
        attack_path: list[dict[str, Any]] | None = None,
    ) -> PentestReport:
        """Generate a complete report from scan findings."""
        self._counter += 1

        # 1 — Narrative
        narrative = None
        if attack_path:
            narrative = self._narrative_gen.generate(scan_id, attack_path)

        # 2 — Evidence
        evidence = self._evidence_ext.extract(findings)

        # 3 — Risk prioritization
        ranked = self._risk_pri.prioritize(findings)

        # 4 — Compliance mapping
        compliance = self._compliance.map_findings(findings)

        # 5 — Executive summary
        exec_summary = self._executive_summary(scan_id, ranked, narrative)

        report = PentestReport(
            report_id=f"report:{self._counter}",
            scan_id=scan_id,
            executive_summary=exec_summary,
            narrative=narrative,
            vulnerabilities=ranked,
            evidence=evidence,
            compliance=compliance,
        )

        logger.info("Report generated: %d vulns, %d evidence, %s",
                     len(ranked), len(evidence), report.report_id)
        return report

    def _executive_summary(
        self, scan_id: str,
        ranked: list[RankedVulnerability],
        narrative: AttackNarrative | None,
    ) -> str:
        if not ranked:
            return f"Penetration test of {scan_id} found no vulnerabilities."

        crit = sum(1 for v in ranked if v.severity == "critical")
        high = sum(1 for v in ranked if v.severity == "high")
        med = sum(1 for v in ranked if v.severity == "medium")

        parts = [f"Penetration test of {scan_id} identified {len(ranked)} vulnerabilities"]
        if crit:
            parts.append(f"including {crit} critical")
        if high:
            parts.append(f"{high} high")
        if med:
            parts.append(f"{med} medium severity issues")
        summary = ", ".join(parts) + "."

        if narrative and narrative.impact:
            summary += f" {narrative.impact}"

        return summary
