"""Pattern registry — loads and validates structured attack patterns from YAML.

MOD-09.5 Offensive Knowledge Engine: Provides a lookup API for attack
patterns used by the PatternMatcher and PatternExecutor.
"""

from __future__ import annotations

__classification__ = "runtime_optional"

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_PATTERNS_DIR = Path(__file__).parent / "patterns"


@dataclass
class PatternAction:
    """A single action within an attack pattern."""

    tool: str
    worker_family: str
    timeout: int
    description: str


@dataclass
class PatternPrecondition:
    """A required artifact precondition for an attack pattern."""

    artifact_type: str   # graph node type: asset | service | endpoint | vulnerability | credential
    filter: dict = field(default_factory=dict)


@dataclass
class AttackPattern:
    """A structured attack pattern loaded from YAML."""

    name: str
    domain: str          # web | network | cloud
    description: str
    preconditions: list[PatternPrecondition]
    actions: list[PatternAction]
    impact: list[str]
    confidence_score: float = 0.5
    priority: str = "medium"  # critical | high | medium | low
    generated_artifacts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "domain": self.domain,
            "description": self.description,
            "confidence_score": self.confidence_score,
            "priority": self.priority,
            "preconditions": [
                {"artifact_type": p.artifact_type, "filter": p.filter}
                for p in self.preconditions
            ],
            "actions": [
                {"tool": a.tool, "worker_family": a.worker_family, "description": a.description}
                for a in self.actions
            ],
            "impact": self.impact,
            "generated_artifacts": self.generated_artifacts,
        }


class PatternRegistry:
    """Loads, validates, and provides lookup for attack patterns.

    Usage::

        registry = PatternRegistry()
        registry.load()
        patterns = registry.get_patterns(domain="web")
    """

    def __init__(self, patterns_dir: Path | str | None = None) -> None:
        self._patterns_dir = Path(patterns_dir) if patterns_dir else _PATTERNS_DIR
        self._patterns: list[AttackPattern] = []
        self._by_name: dict[str, AttackPattern] = {}
        self._by_domain: dict[str, list[AttackPattern]] = {}

    @property
    def patterns(self) -> list[AttackPattern]:
        return list(self._patterns)

    @property
    def count(self) -> int:
        return len(self._patterns)

    def load(self) -> int:
        """Load all YAML pattern files from the patterns directory.

        Returns number of patterns loaded.
        """
        self._patterns.clear()
        self._by_name.clear()
        self._by_domain.clear()

        if not self._patterns_dir.exists():
            logger.warning("Patterns directory not found: %s", self._patterns_dir)
            return 0

        for yaml_file in sorted(self._patterns_dir.glob("*.yaml")):
            try:
                self._load_file(yaml_file)
            except Exception:
                logger.exception("Failed to load pattern file: %s", yaml_file)

        logger.info(
            "Loaded %d attack patterns from %s",
            len(self._patterns), self._patterns_dir,
        )
        return len(self._patterns)

    def _load_file(self, path: Path) -> None:
        """Parse a single YAML pattern file."""
        with open(path) as f:
            data = yaml.safe_load(f)

        if not data or "patterns" not in data:
            return

        for raw in data["patterns"]:
            pattern = self._parse_pattern(raw)
            if pattern and self._validate(pattern):
                self._patterns.append(pattern)
                self._by_name[pattern.name] = pattern
                self._by_domain.setdefault(pattern.domain, []).append(pattern)

    def _parse_pattern(self, raw: dict) -> AttackPattern | None:
        """Parse a single pattern dict into an AttackPattern."""
        try:
            preconds = []
            for p in raw.get("preconditions", {}).get("artifacts", []):
                preconds.append(PatternPrecondition(
                    artifact_type=p["type"],
                    filter=p.get("filter", {}),
                ))

            actions = []
            for a in raw.get("actions", []):
                actions.append(PatternAction(
                    tool=a["tool"],
                    worker_family=a.get("worker_family", "exploit"),
                    timeout=a.get("timeout", 300),
                    description=a.get("description", ""),
                ))

            return AttackPattern(
                name=raw["name"],
                domain=raw.get("domain", "unknown"),
                description=raw.get("description", ""),
                preconditions=preconds,
                actions=actions,
                impact=raw.get("impact", []),
                confidence_score=float(raw.get("confidence_score", 0.5)),
                priority=raw.get("priority", "medium"),
                generated_artifacts=raw.get("generated_artifacts", []),
            )
        except (KeyError, TypeError) as e:
            logger.warning("Failed to parse pattern: %s — %s", raw.get("name", "?"), e)
            return None

    def _validate(self, pattern: AttackPattern) -> bool:
        """Validate a pattern has required fields."""
        if not pattern.name:
            return False
        if not pattern.preconditions:
            return False
        if not pattern.actions:
            return False
        if pattern.name in self._by_name:
            logger.warning("Duplicate pattern name: %s", pattern.name)
            return False
        return True

    def get_pattern(self, name: str) -> AttackPattern | None:
        return self._by_name.get(name)

    def get_patterns(self, *, domain: str | None = None) -> list[AttackPattern]:
        if domain:
            return list(self._by_domain.get(domain, []))
        return list(self._patterns)

    def get_domains(self) -> list[str]:
        return sorted(self._by_domain.keys())
