"""Expansion engine — triggers new recon when sensitive artifacts appear.

MOD-12.5: Monitors newly discovered assets and generates expansion
hypotheses to broaden the attack surface (secret scanning, cloud
enumeration, network scanning, etc.).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.hypothesis_generator import Hypothesis
from app.engine.asset_graph_builder import AssetGraph, AssetNode

logger = logging.getLogger(__name__)


@dataclass
class ExpansionRule:
    """A rule that triggers expansion on certain asset discoveries."""

    name: str
    trigger_asset_type: str       # credential | repository | cloud_resource | network | service
    trigger_domain: str           # web | cloud | network | identity | code | *
    trigger_keywords: list[str]   # keywords in label
    expansion_type: str           # secret_scan | cloud_enum | network_scan | code_audit | identity_enum
    tool: str
    worker_family: str
    priority: float
    description: str


# ── Built-in expansion rules ────────────────────────────────────

_EXPANSION_RULES: list[ExpansionRule] = [
    ExpansionRule(
        name="github_secret_scan",
        trigger_asset_type="repository", trigger_domain="code",
        trigger_keywords=["github", "gitlab", "bitbucket", "repo"],
        expansion_type="secret_scan", tool="trufflehog", worker_family="recon",
        priority=0.9, description="Repository discovered — scan for leaked secrets",
    ),
    ExpansionRule(
        name="api_key_cloud_enum",
        trigger_asset_type="credential", trigger_domain="identity",
        trigger_keywords=["api_key", "aws", "gcp", "azure", "token"],
        expansion_type="cloud_enum", tool="cloudenum", worker_family="recon",
        priority=0.85, description="API key discovered — enumerate cloud resources",
    ),
    ExpansionRule(
        name="vpn_network_scan",
        trigger_asset_type="network", trigger_domain="network",
        trigger_keywords=["vpn", "tunnel", "internal", "private"],
        expansion_type="network_scan", tool="nmap", worker_family="recon",
        priority=0.8, description="VPN/network endpoint discovered — internal scan",
    ),
    ExpansionRule(
        name="credential_identity_enum",
        trigger_asset_type="credential", trigger_domain="identity",
        trigger_keywords=["password", "credential", "admin", "root"],
        expansion_type="identity_enum", tool="ldapenum", worker_family="recon",
        priority=0.75, description="Credential discovered — enumerate identity systems",
    ),
    ExpansionRule(
        name="cloud_resource_deep_scan",
        trigger_asset_type="cloud_resource", trigger_domain="cloud",
        trigger_keywords=["s3", "ec2", "rds", "lambda", "bucket"],
        expansion_type="cloud_enum", tool="cloudenum", worker_family="recon",
        priority=0.8, description="Cloud resource discovered — deep cloud enumeration",
    ),
    ExpansionRule(
        name="subdomain_web_crawl",
        trigger_asset_type="subdomain", trigger_domain="web",
        trigger_keywords=[],
        expansion_type="web_crawl", tool="katana", worker_family="recon",
        priority=0.7, description="New subdomain — crawl for endpoints",
    ),
    ExpansionRule(
        name="service_fingerprint",
        trigger_asset_type="service", trigger_domain="network",
        trigger_keywords=["ssh", "ftp", "rdp", "smb", "telnet"],
        expansion_type="service_enum", tool="nmap", worker_family="recon",
        priority=0.7, description="Sensitive service — fingerprint and enumerate",
    ),
]


class ExpansionEngine:
    """Triggers expansion hypotheses when sensitive assets appear.

    Usage::

        engine = ExpansionEngine()
        hypotheses = engine.expand(asset_graph, new_assets)
    """

    def __init__(self, rules: list[ExpansionRule] | None = None) -> None:
        self._rules = rules or _EXPANSION_RULES

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def expand(
        self,
        graph: AssetGraph,
        new_assets: list[AssetNode] | None = None,
    ) -> list[Hypothesis]:
        """Generate expansion hypotheses for new or all assets."""
        targets = new_assets or list(graph.nodes.values())
        hypotheses: list[Hypothesis] = []

        for asset in targets:
            for rule in self._rules:
                if self._matches(asset, rule):
                    hyp = self._create_hypothesis(asset, rule)
                    hypotheses.append(hyp)

        hypotheses.sort(key=lambda h: h.estimated_complexity, reverse=True)
        logger.info("ExpansionEngine: %d hypotheses from %d assets",
                     len(hypotheses), len(targets))
        return hypotheses

    def _matches(self, asset: AssetNode, rule: ExpansionRule) -> bool:
        if rule.trigger_asset_type != asset.asset_type:
            return False
        if rule.trigger_domain != "*" and rule.trigger_domain != asset.domain:
            return False
        if rule.trigger_keywords:
            label_lower = asset.label.lower()
            return any(kw in label_lower for kw in rule.trigger_keywords)
        return True  # Empty keywords = match all of that type

    def _create_hypothesis(self, asset: AssetNode, rule: ExpansionRule) -> Hypothesis:
        return Hypothesis(
            hypothesis_id=f"expand:{rule.name}:{asset.id}",
            hypothesis_type=f"surface_expansion_{rule.expansion_type}",
            target_node_id=asset.id,
            target_label=asset.label,
            description=rule.description,
            tool=rule.tool,
            worker_family=rule.worker_family,
            config={
                "expansion_type": rule.expansion_type,
                "asset_type": asset.asset_type,
                "domain": asset.domain,
                "priority": rule.priority,
                "no_persist": True,
            },
            required_artifacts=[asset.asset_type],
            estimated_complexity=int(rule.priority * 10),
        )
