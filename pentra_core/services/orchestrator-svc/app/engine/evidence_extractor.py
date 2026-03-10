"""Evidence extractor — extracts proof artifacts from scan results.

MOD-14: Pulls HTTP requests, responses, payloads, and exploit results
from attack graph nodes and formats them as structured evidence for
inclusion in security reports.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EvidenceItem:
    """A single piece of evidence."""

    evidence_id: str
    evidence_type: str      # request | response | payload | exploit_result | screenshot | log
    target: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    severity: str = "info"  # critical | high | medium | low | info

    def to_dict(self) -> dict:
        return {
            "id": self.evidence_id, "type": self.evidence_type,
            "target": self.target, "severity": self.severity,
            "content_preview": self.content[:200],
        }

    def to_markdown(self) -> str:
        lines = [f"### Evidence: {self.evidence_id}", f"**Type:** {self.evidence_type}",
                 f"**Target:** {self.target}", f"**Severity:** {self.severity}", "",
                 "```", self.content[:500], "```"]
        return "\n".join(lines)


class EvidenceExtractor:
    """Extracts evidence from attack graph nodes.

    Usage::

        extractor = EvidenceExtractor()
        evidence = extractor.extract(findings)
    """

    def __init__(self) -> None:
        self._counter = 0

    def extract(self, findings: list[dict[str, Any]]) -> list[EvidenceItem]:
        """Extract evidence from a list of vulnerability findings."""
        evidence: list[EvidenceItem] = []

        for finding in findings:
            target = finding.get("target", finding.get("endpoint", "unknown"))
            vuln_type = finding.get("vulnerability_type", finding.get("type", ""))

            # HTTP request evidence
            if "request" in finding:
                self._counter += 1
                evidence.append(EvidenceItem(
                    evidence_id=f"ev:{self._counter}",
                    evidence_type="request",
                    target=target,
                    content=str(finding["request"]),
                    severity=finding.get("severity", "medium"),
                    metadata={"vuln_type": vuln_type},
                ))

            # HTTP response evidence
            if "response" in finding:
                self._counter += 1
                evidence.append(EvidenceItem(
                    evidence_id=f"ev:{self._counter}",
                    evidence_type="response",
                    target=target,
                    content=str(finding["response"]),
                    severity=finding.get("severity", "medium"),
                    metadata={"status_code": finding.get("status_code", 0)},
                ))

            # Payload evidence
            if "payload" in finding:
                self._counter += 1
                evidence.append(EvidenceItem(
                    evidence_id=f"ev:{self._counter}",
                    evidence_type="payload",
                    target=target,
                    content=str(finding["payload"]),
                    severity=finding.get("severity", "high"),
                    metadata={"mutation": finding.get("mutation", "")},
                ))

            # Exploit result
            if "exploit_result" in finding:
                self._counter += 1
                evidence.append(EvidenceItem(
                    evidence_id=f"ev:{self._counter}",
                    evidence_type="exploit_result",
                    target=target,
                    content=str(finding["exploit_result"]),
                    severity="critical",
                    metadata={"verified": finding.get("verified", False)},
                ))

        evidence.sort(key=lambda e: _SEVERITY_ORDER.get(e.severity, 5))
        logger.info("EvidenceExtractor: %d items from %d findings", len(evidence), len(findings))
        return evidence

    def group_by_target(self, evidence: list[EvidenceItem]) -> dict[str, list[EvidenceItem]]:
        groups: dict[str, list[EvidenceItem]] = {}
        for e in evidence:
            groups.setdefault(e.target, []).append(e)
        return groups


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
