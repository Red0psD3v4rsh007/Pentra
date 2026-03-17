"""Attack narrative generator — human-readable attack story.

MOD-14: Converts attack graph paths into a human-readable chronological
narrative describing how an attacker could compromise the target.
"""

from __future__ import annotations

__classification__ = "experimental"

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class NarrativeStep:
    """A single step in the attack narrative."""

    step_number: int
    action: str           # discovery | exploitation | credential_extraction | lateral_movement | privilege_escalation
    description: str
    target: str
    technique: str = ""
    evidence_ref: str = ""
    risk_level: str = ""  # critical | high | medium | low

    def to_dict(self) -> dict:
        return {
            "step": self.step_number, "action": self.action,
            "description": self.description, "target": self.target,
            "technique": self.technique, "risk": self.risk_level,
        }


@dataclass
class AttackNarrative:
    """Complete attack narrative."""

    scan_id: str
    title: str
    summary: str
    steps: list[NarrativeStep] = field(default_factory=list)
    impact: str = ""
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id, "title": self.title,
            "summary": self.summary,
            "steps": [s.to_dict() for s in self.steps],
            "impact": self.impact,
            "recommendations": self.recommendations,
        }

    def to_markdown(self) -> str:
        lines = [f"# {self.title}", "", f"**Summary:** {self.summary}", "", "## Attack Path", ""]
        for s in self.steps:
            risk_badge = f" [{s.risk_level.upper()}]" if s.risk_level else ""
            lines.append(f"**Step {s.step_number}** — {s.action}{risk_badge}")
            lines.append(f"  {s.description}")
            if s.technique:
                lines.append(f"  *Technique:* {s.technique}")
            lines.append("")
        if self.impact:
            lines.extend(["## Impact", "", self.impact, ""])
        if self.recommendations:
            lines.extend(["## Recommendations", ""])
            for r in self.recommendations:
                lines.append(f"- {r}")
        return "\n".join(lines)


# ── Action classification ───────────────────────────────────────

_ACTION_MAP = {
    "entrypoint": "discovery", "asset": "discovery", "subdomain": "discovery",
    "endpoint": "discovery", "service": "discovery",
    "vulnerability": "exploitation", "exploit": "exploitation",
    "credential": "credential_extraction", "credential_leak": "credential_extraction",
    "privilege": "privilege_escalation", "access": "lateral_movement",
    "database_access": "privilege_escalation", "shell_access": "privilege_escalation",
}

_RISK_MAP = {
    "exploitation": "high", "credential_extraction": "critical",
    "privilege_escalation": "critical", "lateral_movement": "high",
    "discovery": "medium",
}

_RECOMMENDATIONS = {
    "exploitation": "Patch the identified vulnerability and implement input validation.",
    "credential_extraction": "Rotate all exposed credentials and enforce MFA.",
    "privilege_escalation": "Review privilege boundaries and apply least-privilege access.",
    "lateral_movement": "Segment networks and restrict inter-service communication.",
    "discovery": "Reduce attack surface by removing unnecessary exposed services.",
}


class AttackNarrativeGenerator:
    """Generates attack narratives from attack graph paths.

    Usage::

        gen = AttackNarrativeGenerator()
        narrative = gen.generate(scan_id, attack_path_nodes)
    """

    def generate(self, scan_id: str, path_nodes: list[dict[str, Any]]) -> AttackNarrative:
        """Generate a narrative from an ordered list of attack path nodes."""
        steps: list[NarrativeStep] = []
        actions_seen: set[str] = set()
        recommendations: list[str] = []

        for i, node in enumerate(path_nodes, 1):
            node_type = node.get("node_type", node.get("type", "unknown"))
            label = node.get("label", "unknown target")
            technique = node.get("technique", node.get("exploit_type", ""))
            action = _ACTION_MAP.get(node_type, "discovery")
            risk = _RISK_MAP.get(action, "low")

            steps.append(NarrativeStep(
                step_number=i,
                action=action,
                description=self._describe(action, label, technique),
                target=label,
                technique=technique,
                evidence_ref=node.get("artifact_ref", ""),
                risk_level=risk,
            ))

            if action not in actions_seen:
                actions_seen.add(action)
                if action in _RECOMMENDATIONS:
                    recommendations.append(_RECOMMENDATIONS[action])

        highest_risk = "critical" if any(s.risk_level == "critical" for s in steps) else "high"
        title = f"Attack Path Analysis — {scan_id}"
        summary = f"{len(steps)}-step attack path with {highest_risk} risk impact."
        impact = self._compute_impact(steps)

        narrative = AttackNarrative(
            scan_id=scan_id, title=title, summary=summary,
            steps=steps, impact=impact, recommendations=recommendations,
        )
        logger.info("Narrative: %d steps, %s risk", len(steps), highest_risk)
        return narrative

    def _describe(self, action: str, label: str, technique: str) -> str:
        descs = {
            "discovery": f"Discovered {label} through reconnaissance.",
            "exploitation": f"Exploited {label}" + (f" using {technique}." if technique else "."),
            "credential_extraction": f"Extracted credentials from {label}.",
            "privilege_escalation": f"Escalated privileges via {label}.",
            "lateral_movement": f"Moved laterally to {label}.",
        }
        return descs.get(action, f"Interacted with {label}.")

    def _compute_impact(self, steps: list[NarrativeStep]) -> str:
        actions = {s.action for s in steps}
        if "privilege_escalation" in actions:
            return "Full system compromise possible. Attacker can escalate privileges and access sensitive data."
        if "credential_extraction" in actions:
            return "Credential exposure enables unauthorized access to internal systems."
        if "exploitation" in actions:
            return "Vulnerability exploitation allows data access and potential further compromise."
        return "Reconnaissance reveals attack surface that could be exploited."
