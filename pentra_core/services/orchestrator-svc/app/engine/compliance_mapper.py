"""Compliance mapper — maps vulnerabilities to security frameworks.

MOD-14: Maps vulnerability types to OWASP Top 10, MITRE ATT&CK
techniques, and CWE identifiers for compliance reporting.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ComplianceMapping:
    """Compliance mapping for a vulnerability."""

    vuln_type: str
    owasp: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"vuln_type": self.vuln_type, "owasp": self.owasp, "mitre": self.mitre, "cwe": self.cwe}


# ── OWASP Top 10 (2021) ────────────────────────────────────────

_OWASP: dict[str, list[str]] = {
    "sqli": ["A03:2021-Injection"],
    "sql_injection": ["A03:2021-Injection"],
    "xss": ["A03:2021-Injection", "A07:2021-XSS"],
    "idor": ["A01:2021-Broken Access Control"],
    "ssrf": ["A10:2021-SSRF"],
    "rce": ["A03:2021-Injection"],
    "credential": ["A07:2021-Auth Failures"],
    "auth_bypass": ["A01:2021-Broken Access Control", "A07:2021-Auth Failures"],
    "privilege_escalation": ["A01:2021-Broken Access Control"],
    "csrf": ["A01:2021-Broken Access Control"],
    "path_traversal": ["A01:2021-Broken Access Control"],
    "deserialization": ["A08:2021-Insecure Deserialization"],
    "misconfiguration": ["A05:2021-Security Misconfiguration"],
    "sensitive_data": ["A02:2021-Cryptographic Failures"],
    "outdated_component": ["A06:2021-Vulnerable Components"],
}

# ── MITRE ATT&CK ───────────────────────────────────────────────

_MITRE: dict[str, list[str]] = {
    "sqli": ["T1190-Exploit Public-Facing Application"],
    "sql_injection": ["T1190-Exploit Public-Facing Application"],
    "xss": ["T1189-Drive-by Compromise"],
    "idor": ["T1078-Valid Accounts"],
    "ssrf": ["T1190-Exploit Public-Facing Application"],
    "rce": ["T1059-Command and Scripting"],
    "credential": ["T1078-Valid Accounts", "T1552-Unsecured Credentials"],
    "auth_bypass": ["T1078-Valid Accounts"],
    "privilege_escalation": ["T1068-Exploitation for Privilege Escalation"],
    "lateral_movement": ["T1021-Remote Services"],
    "path_traversal": ["T1083-File and Directory Discovery"],
}

# ── CWE ────────────────────────────────────────────────────────

_CWE: dict[str, list[str]] = {
    "sqli": ["CWE-89"],
    "sql_injection": ["CWE-89"],
    "xss": ["CWE-79"],
    "idor": ["CWE-639"],
    "ssrf": ["CWE-918"],
    "rce": ["CWE-78", "CWE-94"],
    "credential": ["CWE-798", "CWE-522"],
    "auth_bypass": ["CWE-287"],
    "privilege_escalation": ["CWE-269"],
    "csrf": ["CWE-352"],
    "path_traversal": ["CWE-22"],
    "deserialization": ["CWE-502"],
}


class ComplianceMapper:
    """Maps vulnerabilities to compliance frameworks.

    Usage::

        mapper = ComplianceMapper()
        mappings = mapper.map_findings(findings)
    """

    def map_finding(self, vuln_type: str) -> ComplianceMapping:
        """Map a single vulnerability type to frameworks."""
        key = vuln_type.lower().replace(" ", "_")
        return ComplianceMapping(
            vuln_type=vuln_type,
            owasp=self._lookup(key, _OWASP),
            mitre=self._lookup(key, _MITRE),
            cwe=self._lookup(key, _CWE),
        )

    def map_findings(self, findings: list[dict[str, Any]]) -> list[ComplianceMapping]:
        """Map multiple findings."""
        mappings: list[ComplianceMapping] = []
        for f in findings:
            vuln_type = f.get("vulnerability_type", f.get("type", "unknown"))
            mappings.append(self.map_finding(vuln_type))
        return mappings

    def coverage_summary(self, mappings: list[ComplianceMapping]) -> dict[str, Any]:
        owasp_set: set[str] = set()
        mitre_set: set[str] = set()
        cwe_set: set[str] = set()
        for m in mappings:
            owasp_set.update(m.owasp)
            mitre_set.update(m.mitre)
            cwe_set.update(m.cwe)
        return {
            "owasp_categories": len(owasp_set),
            "mitre_techniques": len(mitre_set),
            "cwe_weaknesses": len(cwe_set),
        }

    def _lookup(self, key: str, db: dict[str, list[str]]) -> list[str]:
        if key in db:
            return list(db[key])
        for dbkey in db:
            if dbkey in key or key in dbkey:
                return list(db[dbkey])
        return []
