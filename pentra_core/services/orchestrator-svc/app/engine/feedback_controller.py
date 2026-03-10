"""Feedback loop controller — monitors results and triggers new strategies.

MOD-12: Watches executed action results and dynamically triggers
new reconnaissance, exploitation, or exploration strategies based
on discoveries (credential → lateral recon, vuln → exploit chain, etc.).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FeedbackEvent:
    """An event from a completed offensive action."""

    event_type: str          # credential_found | vulnerability_confirmed | access_gained | recon_complete | exploit_failed
    source_action: str
    artifacts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "source": self.source_action,
        }


@dataclass
class StrategicTrigger:
    """A new strategy triggered by feedback."""

    trigger_id: str
    trigger_type: str        # lateral_recon | exploit_escalation | surface_expansion | credential_spray | deep_scan
    priority: float
    description: str
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "trigger_id": self.trigger_id,
            "trigger_type": self.trigger_type,
            "priority": round(self.priority, 3),
            "description": self.description,
        }


# ── Feedback rules ───────────────────────────────────────────────

_FEEDBACK_RULES: list[dict[str, Any]] = [
    {
        "event": "credential_found",
        "trigger_type": "credential_spray",
        "priority": 0.9,
        "description": "Credential discovered — spray against all services",
    },
    {
        "event": "credential_found",
        "trigger_type": "lateral_recon",
        "priority": 0.8,
        "description": "Credential discovered — recon internal services",
    },
    {
        "event": "vulnerability_confirmed",
        "trigger_type": "exploit_escalation",
        "priority": 0.85,
        "description": "Vulnerability confirmed — attempt privilege escalation chain",
    },
    {
        "event": "access_gained",
        "trigger_type": "deep_scan",
        "priority": 0.9,
        "description": "Access gained — deep scan internal network from foothold",
    },
    {
        "event": "access_gained",
        "trigger_type": "lateral_recon",
        "priority": 0.85,
        "description": "Access gained — lateral movement reconnaissance",
    },
    {
        "event": "recon_complete",
        "trigger_type": "surface_expansion",
        "priority": 0.6,
        "description": "Recon completed — expand attack surface with new findings",
    },
    {
        "event": "exploit_failed",
        "trigger_type": "surface_expansion",
        "priority": 0.4,
        "description": "Exploit failed — explore alternative attack vectors",
    },
]


class FeedbackController:
    """Monitors action results and triggers new offensive strategies.

    Usage::

        ctrl = FeedbackController()
        triggers = ctrl.process(event)
    """

    def __init__(self) -> None:
        self._event_history: list[FeedbackEvent] = []
        self._trigger_count = 0

    @property
    def event_count(self) -> int:
        return len(self._event_history)

    def process(self, event: FeedbackEvent) -> list[StrategicTrigger]:
        """Process a feedback event and return triggered strategies."""
        self._event_history.append(event)
        triggers: list[StrategicTrigger] = []

        for rule in _FEEDBACK_RULES:
            if rule["event"] == event.event_type:
                self._trigger_count += 1
                triggers.append(StrategicTrigger(
                    trigger_id=f"trigger:{self._trigger_count}",
                    trigger_type=rule["trigger_type"],
                    priority=rule["priority"],
                    description=rule["description"],
                    config={
                        "source_event": event.event_type,
                        "source_action": event.source_action,
                        "artifacts": event.artifacts,
                    },
                ))

        logger.info(
            "FeedbackController: event=%s → %d triggers",
            event.event_type, len(triggers),
        )
        return triggers

    def process_batch(self, events: list[FeedbackEvent]) -> list[StrategicTrigger]:
        """Process multiple events."""
        all_triggers: list[StrategicTrigger] = []
        for event in events:
            all_triggers.extend(self.process(event))
        return all_triggers

    def summary(self) -> dict[str, Any]:
        event_counts: dict[str, int] = {}
        for e in self._event_history:
            event_counts[e.event_type] = event_counts.get(e.event_type, 0) + 1
        return {
            "total_events": len(self._event_history),
            "total_triggers": self._trigger_count,
            "event_counts": event_counts,
        }
