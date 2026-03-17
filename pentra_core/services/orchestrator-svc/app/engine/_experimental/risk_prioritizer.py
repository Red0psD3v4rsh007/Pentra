"""Risk prioritizer — ranks vulnerabilities by risk.

MOD-14: Scores vulnerabilities using CVSS, exploit verification status,
asset criticality, and attack path impact to produce a ranked list
for executive reporting.
"""

from __future__ import annotations

__classification__ = "experimental"

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RankedVulnerability:
    """A vulnerability with computed risk score."""

    vuln_id: str
    title: str
    target: str
    risk_score: float        # 0.0–10.0
    severity: str            # critical | high | medium | low | info
    factors: dict[str, float] = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.vuln_id, "title": self.title, "target": self.target,
            "risk_score": round(self.risk_score, 2), "severity": self.severity,
            "remediation": self.remediation,
        }


# ── Scoring weights ──────────────────────────────────────────────

_WEIGHTS = {
    "cvss": 0.30,
    "exploitability": 0.25,
    "asset_criticality": 0.20,
    "path_impact": 0.15,
    "exposure": 0.10,
}

_SEVERITY_MAP = {
    (9.0, 10.1): "critical",
    (7.0, 9.0): "high",
    (4.0, 7.0): "medium",
    (2.0, 4.0): "low",
    (0.0, 2.0): "info",
}


class RiskPrioritizer:
    """Ranks vulnerabilities by composite risk score.

    Usage::

        prioritizer = RiskPrioritizer()
        ranked = prioritizer.prioritize(findings)
    """

    def prioritize(self, findings: list[dict[str, Any]]) -> list[RankedVulnerability]:
        """Score and rank vulnerability findings."""
        ranked: list[RankedVulnerability] = []

        for finding in findings:
            factors = self._compute_factors(finding)
            score = sum(_WEIGHTS.get(k, 0) * v for k, v in factors.items()) * 10
            score = min(10.0, max(0.0, score))
            severity = self._classify(score)

            ranked.append(RankedVulnerability(
                vuln_id=finding.get("id", f"vuln:{len(ranked)}"),
                title=finding.get("title", finding.get("vulnerability_type", "Unknown")),
                target=finding.get("target", "unknown"),
                risk_score=score,
                severity=severity,
                factors=factors,
                remediation=self._remediation(finding),
            ))

        ranked.sort(key=lambda r: r.risk_score, reverse=True)
        logger.info("RiskPrioritizer: %d vulns ranked (max: %.1f)",
                     len(ranked), ranked[0].risk_score if ranked else 0)
        return ranked

    def top_risks(self, findings: list[dict], n: int = 5) -> list[RankedVulnerability]:
        return self.prioritize(findings)[:n]

    def summary(self, ranked: list[RankedVulnerability]) -> dict[str, Any]:
        levels: dict[str, int] = {}
        for r in ranked:
            levels[r.severity] = levels.get(r.severity, 0) + 1
        return {
            "total": len(ranked),
            "max_score": round(ranked[0].risk_score, 2) if ranked else 0,
            "levels": levels,
        }

    def _compute_factors(self, finding: dict) -> dict[str, float]:
        factors: dict[str, float] = {}

        # CVSS: provided or estimated
        factors["cvss"] = min(1.0, finding.get("cvss", 5.0) / 10.0)

        # Exploitability: verified exploits score highest
        if finding.get("verified", False):
            factors["exploitability"] = 1.0
        elif finding.get("exploit_result"):
            factors["exploitability"] = 0.8
        elif finding.get("payload"):
            factors["exploitability"] = 0.5
        else:
            factors["exploitability"] = 0.2

        # Asset criticality
        target = finding.get("target", "").lower()
        if any(kw in target for kw in ("admin", "database", "root", "ssh", "api")):
            factors["asset_criticality"] = 0.9
        elif any(kw in target for kw in ("login", "auth", "user", "account")):
            factors["asset_criticality"] = 0.7
        else:
            factors["asset_criticality"] = 0.4

        # Attack path impact
        factors["path_impact"] = min(1.0, finding.get("chain_length", 1) * 0.2)

        # Exposure
        factors["exposure"] = 0.8 if finding.get("external", True) else 0.3

        return factors

    def _classify(self, score: float) -> str:
        for (lo, hi), label in _SEVERITY_MAP.items():
            if lo <= score < hi:
                return label
        return "info"

    def _remediation(self, finding: dict) -> str:
        vuln_type = finding.get("vulnerability_type", "").lower()
        remediations = {
            "sqli": "Use parameterized queries and input validation.",
            "sql_injection": "Use parameterized queries and input validation.",
            "xss": "Implement output encoding and Content Security Policy.",
            "idor": "Enforce server-side authorization checks on resource access.",
            "ssrf": "Restrict outbound requests and validate URLs server-side.",
            "rce": "Eliminate code execution vectors and sandbox untrusted input.",
            "credential": "Rotate credentials and enforce MFA.",
        }
        for key, remedy in remediations.items():
            if key in vuln_type:
                return remedy
        return "Review and patch the identified vulnerability."
