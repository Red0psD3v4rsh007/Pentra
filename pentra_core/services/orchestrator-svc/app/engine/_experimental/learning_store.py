"""Learning store — historical attack telemetry storage.

MOD-13: Stores successful exploit chains, failed attempts, payload
effectiveness, and WAF bypass techniques. Data is held in memory
and can be serialized for persistence.
"""

from __future__ import annotations

__classification__ = "experimental"

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ExploitRecord:
    """Record of an exploit attempt."""

    record_id: str
    exploit_type: str       # sqli | xss | idor | rce | ssrf | credential_reuse | etc.
    target: str
    tool: str
    success: bool
    payload: str = ""
    waf_bypassed: bool = False
    bypass_technique: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.record_id, "type": self.exploit_type,
            "target": self.target, "success": self.success,
            "waf_bypassed": self.waf_bypassed,
        }


@dataclass
class ChainRecord:
    """Record of a successful attack chain."""

    chain_id: str
    steps: list[str]          # ordered exploit types
    target_tech: str          # technology fingerprint
    success: bool
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"id": self.chain_id, "steps": self.steps, "tech": self.target_tech, "success": self.success}


class LearningStore:
    """Central store for attack telemetry.

    Usage::

        store = LearningStore()
        store.record_exploit(record)
        stats = store.get_exploit_stats("sqli")
    """

    def __init__(self) -> None:
        self._exploits: list[ExploitRecord] = []
        self._chains: list[ChainRecord] = []
        self._payload_records: list[dict[str, Any]] = []
        self._waf_bypasses: list[dict[str, Any]] = []

    @property
    def exploit_count(self) -> int:
        return len(self._exploits)

    @property
    def chain_count(self) -> int:
        return len(self._chains)

    def record_exploit(self, record: ExploitRecord) -> None:
        self._exploits.append(record)
        if record.waf_bypassed:
            self._waf_bypasses.append({
                "technique": record.bypass_technique,
                "exploit_type": record.exploit_type,
                "target": record.target,
            })

    def record_chain(self, record: ChainRecord) -> None:
        self._chains.append(record)

    def record_payload(self, payload_type: str, mutation: str, success: bool,
                        false_positive: bool = False) -> None:
        self._payload_records.append({
            "payload_type": payload_type, "mutation": mutation,
            "success": success, "false_positive": false_positive,
        })

    def get_exploits(self, exploit_type: str | None = None) -> list[ExploitRecord]:
        if exploit_type:
            return [e for e in self._exploits if e.exploit_type == exploit_type]
        return list(self._exploits)

    def get_chains(self, target_tech: str | None = None) -> list[ChainRecord]:
        if target_tech:
            return [c for c in self._chains if c.target_tech == target_tech]
        return list(self._chains)

    def get_payload_records(self, payload_type: str | None = None) -> list[dict]:
        if payload_type:
            return [p for p in self._payload_records if p["payload_type"] == payload_type]
        return list(self._payload_records)

    def get_waf_bypasses(self) -> list[dict]:
        return list(self._waf_bypasses)

    def get_exploit_stats(self, exploit_type: str) -> dict[str, Any]:
        records = self.get_exploits(exploit_type)
        total = len(records)
        if total == 0:
            return {"type": exploit_type, "total": 0, "success_rate": 0.0}
        successes = sum(1 for r in records if r.success)
        return {
            "type": exploit_type, "total": total,
            "successes": successes, "failures": total - successes,
            "success_rate": round(successes / total, 3),
        }

    def serialize(self) -> str:
        return json.dumps({
            "exploits": [e.to_dict() for e in self._exploits],
            "chains": [c.to_dict() for c in self._chains],
            "payloads": self._payload_records,
            "waf_bypasses": self._waf_bypasses,
        })

    def summary(self) -> dict[str, Any]:
        return {
            "exploits": self.exploit_count, "chains": self.chain_count,
            "payloads": len(self._payload_records),
            "waf_bypasses": len(self._waf_bypasses),
        }
