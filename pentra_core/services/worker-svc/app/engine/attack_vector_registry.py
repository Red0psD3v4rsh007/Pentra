"""Attack Vector Registry — central classification of all vulnerability types.

Organizes 65+ attack vectors into 10 categories with:
  - Required tools per vector
  - Required input types (domain, URL, API spec, credentials, etc.)
  - Detection methods (active_scan, passive_analysis, fuzzing, auth_test)
  - Severity classification
  - MITRE ATT&CK technique mapping

Used by the DAG builder to dynamically construct tool execution graphs
based on target type and scan profile configuration.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Literal

logger = logging.getLogger(__name__)

DetectionMethod = Literal[
    "active_scan", "passive_analysis", "fuzzing",
    "auth_test", "brute_force", "crawling", "config_review",
]

InputType = Literal[
    "url", "domain", "ip", "api_spec", "credentials",
    "jwt_token", "network_range", "subdomain_list",
]

Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass(frozen=True)
class AttackVector:
    """Definition of a single attack vector type."""
    id: str
    name: str
    category: str
    description: str
    severity: Severity
    detection_methods: tuple[DetectionMethod, ...]
    required_tools: tuple[str, ...]
    optional_tools: tuple[str, ...] = ()
    required_inputs: tuple[InputType, ...] = ("url",)
    mitre_technique: str = ""
    mitre_tactic: str = ""
    cwe_id: str = ""
    owasp_category: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "severity": self.severity,
            "detection_methods": list(self.detection_methods),
            "required_tools": list(self.required_tools),
            "optional_tools": list(self.optional_tools),
            "required_inputs": list(self.required_inputs),
            "mitre_technique": self.mitre_technique,
            "cwe_id": self.cwe_id,
        }


ATTACK_VECTOR_REGISTRY: dict[str, AttackVector] = {}


def _reg(v: AttackVector) -> AttackVector:
    ATTACK_VECTOR_REGISTRY[v.id] = v
    return v


# ═══════════════════════════════════════════════════════════════════════
#  CATEGORY 1: INJECTION
# ═══════════════════════════════════════════════════════════════════════

_reg(AttackVector(
    id="sqli", name="SQL Injection", category="injection",
    description="Insert malicious SQL into application queries",
    severity="critical",
    detection_methods=("active_scan", "fuzzing"),
    required_tools=("sqlmap", "nuclei"),
    mitre_technique="T1190", cwe_id="CWE-89",
    owasp_category="A03:2021 Injection",
))
_reg(AttackVector(
    id="blind_sqli", name="Blind SQL Injection", category="injection",
    description="SQL injection via boolean/time-based inference",
    severity="critical",
    detection_methods=("fuzzing",),
    required_tools=("sqlmap",),
    mitre_technique="T1190", cwe_id="CWE-89",
))
_reg(AttackVector(
    id="error_based_sqli", name="Error-Based SQL Injection", category="injection",
    description="SQL injection using error message disclosure",
    severity="critical",
    detection_methods=("active_scan",),
    required_tools=("sqlmap",),
    mitre_technique="T1190", cwe_id="CWE-89",
))
_reg(AttackVector(
    id="xss_reflected", name="Reflected XSS", category="injection",
    description="Reflected cross-site scripting via user input",
    severity="high",
    detection_methods=("active_scan", "fuzzing"),
    required_tools=("nuclei",), optional_tools=("dalfox",),
    mitre_technique="T1059.007", cwe_id="CWE-79",
    owasp_category="A03:2021 Injection",
))
_reg(AttackVector(
    id="xss_stored", name="Stored XSS", category="injection",
    description="Persistent XSS stored in server-side data",
    severity="high",
    detection_methods=("active_scan", "fuzzing"),
    required_tools=("nuclei",), optional_tools=("dalfox",),
    mitre_technique="T1059.007", cwe_id="CWE-79",
))
_reg(AttackVector(
    id="dom_xss", name="DOM-Based XSS", category="injection",
    description="XSS via client-side DOM manipulation",
    severity="high",
    detection_methods=("crawling", "active_scan"),
    required_tools=("dalfox", "web_interact"),
    mitre_technique="T1059.007", cwe_id="CWE-79",
))
_reg(AttackVector(
    id="command_injection", name="Command Injection", category="injection",
    description="OS command injection via application input",
    severity="critical",
    detection_methods=("active_scan", "fuzzing"),
    required_tools=("nuclei",),
    mitre_technique="T1059", cwe_id="CWE-78",
))
_reg(AttackVector(
    id="ssti", name="Server-Side Template Injection", category="injection",
    description="Template engine code injection for RCE",
    severity="critical",
    detection_methods=("fuzzing",),
    required_tools=("nuclei",),
    mitre_technique="T1059", cwe_id="CWE-94",
))
_reg(AttackVector(
    id="xxe", name="XML External Entity", category="injection",
    description="XXE injection for SSRF, file read, or RCE",
    severity="high",
    detection_methods=("active_scan",),
    required_tools=("nuclei",),
    mitre_technique="T1059", cwe_id="CWE-611",
))
_reg(AttackVector(
    id="ldap_injection", name="LDAP Injection", category="injection",
    description="Modify LDAP queries via crafted input",
    severity="high",
    detection_methods=("fuzzing",),
    required_tools=("nuclei",),
    mitre_technique="T1190", cwe_id="CWE-90",
))
_reg(AttackVector(
    id="xpath_injection", name="XPath Injection", category="injection",
    description="Inject into XPath queries for data extraction",
    severity="high",
    detection_methods=("fuzzing",),
    required_tools=("nuclei",),
    mitre_technique="T1190", cwe_id="CWE-643",
))
_reg(AttackVector(
    id="crlf_injection", name="CRLF Injection", category="injection",
    description="Carriage return/line feed injection in HTTP headers",
    severity="medium",
    detection_methods=("active_scan",),
    required_tools=("nuclei",),
    mitre_technique="T1190", cwe_id="CWE-93",
))
_reg(AttackVector(
    id="deserialization", name="Insecure Deserialization", category="injection",
    description="Exploit deserialization flaws for RCE or data manipulation",
    severity="critical",
    detection_methods=("active_scan",),
    required_tools=("nuclei",),
    mitre_technique="T1059", cwe_id="CWE-502",
    owasp_category="A08:2021 Insecure Deserialization",
))

# ═══════════════════════════════════════════════════════════════════════
#  CATEGORY 2: AUTH & SESSION
# ═══════════════════════════════════════════════════════════════════════

_reg(AttackVector(
    id="brute_force", name="Credential Brute Force", category="auth_session",
    description="Brute force authentication endpoints",
    severity="high",
    detection_methods=("brute_force",),
    required_tools=("ffuf",),
    required_inputs=("url", "credentials"),
    mitre_technique="T1110", cwe_id="CWE-307",
))
_reg(AttackVector(
    id="jwt_none_algo", name="JWT None Algorithm", category="auth_session",
    description="Exploit JWT none algorithm to bypass authentication",
    severity="critical",
    detection_methods=("active_scan",),
    required_tools=("jwt_tool", "nuclei"),
    required_inputs=("url", "jwt_token"),
    mitre_technique="T1078", cwe_id="CWE-347",
))
_reg(AttackVector(
    id="jwt_key_confusion", name="JWT Key Confusion", category="auth_session",
    description="Algorithm confusion attack on JWT verification",
    severity="critical",
    detection_methods=("active_scan",),
    required_tools=("jwt_tool",),
    required_inputs=("url", "jwt_token"),
    mitre_technique="T1078", cwe_id="CWE-347",
))
_reg(AttackVector(
    id="jwt_weak_secret", name="JWT Weak Secret", category="auth_session",
    description="Crack JWT HMAC secret with wordlist",
    severity="critical",
    detection_methods=("brute_force",),
    required_tools=("jwt_tool",),
    required_inputs=("url", "jwt_token"),
    mitre_technique="T1110", cwe_id="CWE-326",
))
_reg(AttackVector(
    id="session_fixation", name="Session Fixation", category="auth_session",
    description="Force user to use attacker-controlled session ID",
    severity="high",
    detection_methods=("active_scan",),
    required_tools=("web_interact", "nuclei"),
    mitre_technique="T1563", cwe_id="CWE-384",
))
_reg(AttackVector(
    id="broken_auth", name="Broken Authentication", category="auth_session",
    description="Bypass or circumvent authentication mechanisms",
    severity="critical",
    detection_methods=("active_scan", "auth_test"),
    required_tools=("nuclei", "web_interact"),
    mitre_technique="T1078", cwe_id="CWE-287",
    owasp_category="A07:2021 Auth Failures",
))
_reg(AttackVector(
    id="default_credentials", name="Default Credentials", category="auth_session",
    description="Test for default or common credentials",
    severity="high",
    detection_methods=("brute_force",),
    required_tools=("nuclei", "nikto"),
    mitre_technique="T1078.001", cwe_id="CWE-798",
))
_reg(AttackVector(
    id="password_reset_flaw", name="Password Reset Flaw", category="auth_session",
    description="Exploit password reset flow for account takeover",
    severity="high",
    detection_methods=("active_scan",),
    required_tools=("web_interact",),
    mitre_technique="T1078", cwe_id="CWE-640",
))

# ═══════════════════════════════════════════════════════════════════════
#  CATEGORY 3: FILE & PATH
# ═══════════════════════════════════════════════════════════════════════

_reg(AttackVector(
    id="file_upload_rce", name="File Upload → RCE", category="file_path",
    description="Upload malicious files to achieve remote code execution",
    severity="critical",
    detection_methods=("active_scan",),
    required_tools=("nuclei",),
    mitre_technique="T1105", cwe_id="CWE-434",
))
_reg(AttackVector(
    id="path_traversal", name="Path Traversal", category="file_path",
    description="Access files outside intended directory via ../ sequences",
    severity="high",
    detection_methods=("fuzzing",),
    required_tools=("nuclei", "ffuf"),
    mitre_technique="T1083", cwe_id="CWE-22",
))
_reg(AttackVector(
    id="lfi", name="Local File Inclusion", category="file_path",
    description="Include local files via vulnerable file parameters",
    severity="high",
    detection_methods=("fuzzing",),
    required_tools=("nuclei",),
    mitre_technique="T1083", cwe_id="CWE-98",
))
_reg(AttackVector(
    id="rfi", name="Remote File Inclusion", category="file_path",
    description="Include remote files for code execution",
    severity="critical",
    detection_methods=("fuzzing",),
    required_tools=("nuclei",),
    mitre_technique="T1105", cwe_id="CWE-98",
))
_reg(AttackVector(
    id="zip_slip", name="Zip Slip", category="file_path",
    description="Path traversal via crafted archive extraction",
    severity="high",
    detection_methods=("active_scan",),
    required_tools=("nuclei",),
    mitre_technique="T1105", cwe_id="CWE-22",
))

# ═══════════════════════════════════════════════════════════════════════
#  CATEGORY 4: ACCESS CONTROL
# ═══════════════════════════════════════════════════════════════════════

_reg(AttackVector(
    id="idor", name="Insecure Direct Object Reference", category="access_control",
    description="Access other users' data via predictable references",
    severity="high",
    detection_methods=("active_scan", "auth_test"),
    required_tools=("nuclei", "custom_poc"),
    required_inputs=("url", "credentials"),
    mitre_technique="T1078", cwe_id="CWE-639",
    owasp_category="A01:2021 Broken Access Control",
))
_reg(AttackVector(
    id="bola", name="Broken Object Level Authorization", category="access_control",
    description="API authorization bypass for object-level access",
    severity="critical",
    detection_methods=("auth_test",),
    required_tools=("custom_poc",),
    required_inputs=("url", "credentials"),
    mitre_technique="T1078", cwe_id="CWE-639",
))
_reg(AttackVector(
    id="mass_assignment", name="Mass Assignment", category="access_control",
    description="Modify restricted fields via unfiltered request binding",
    severity="high",
    detection_methods=("active_scan",),
    required_tools=("nuclei", "custom_poc"),
    mitre_technique="T1565", cwe_id="CWE-915",
))
_reg(AttackVector(
    id="forced_browsing", name="Forced Browsing", category="access_control",
    description="Access unlinked admin/debug pages via enumeration",
    severity="medium",
    detection_methods=("fuzzing",),
    required_tools=("ffuf",),
    mitre_technique="T1083", cwe_id="CWE-425",
))
_reg(AttackVector(
    id="privilege_escalation", name="Privilege Escalation", category="access_control",
    description="Gain higher privileges than assigned",
    severity="critical",
    detection_methods=("auth_test",),
    required_tools=("custom_poc", "nuclei"),
    required_inputs=("url", "credentials"),
    mitre_technique="T1078.003", cwe_id="CWE-269",
))
_reg(AttackVector(
    id="horizontal_priv_esc", name="Horizontal Privilege Escalation", category="access_control",
    description="Access other users' resources at the same privilege level",
    severity="high",
    detection_methods=("auth_test",),
    required_tools=("custom_poc",),
    required_inputs=("url", "credentials"),
    mitre_technique="T1078", cwe_id="CWE-639",
))

# ═══════════════════════════════════════════════════════════════════════
#  CATEGORY 5: API
# ═══════════════════════════════════════════════════════════════════════

_reg(AttackVector(
    id="graphql_introspection", name="GraphQL Introspection", category="api",
    description="Expose GraphQL schema via enabled introspection",
    severity="medium",
    detection_methods=("active_scan",),
    required_tools=("graphql_cop", "nuclei"),
    required_inputs=("url",),
    mitre_technique="T1592", cwe_id="CWE-200",
))
_reg(AttackVector(
    id="graphql_dos", name="GraphQL Denial of Service", category="api",
    description="Query complexity/depth attacks against GraphQL",
    severity="medium",
    detection_methods=("active_scan",),
    required_tools=("graphql_cop",),
    required_inputs=("url",),
    mitre_technique="T1499", cwe_id="CWE-400",
))
_reg(AttackVector(
    id="graphql_injection", name="GraphQL Injection", category="api",
    description="Inject into GraphQL queries for data exfiltration",
    severity="high",
    detection_methods=("fuzzing",),
    required_tools=("graphql_cop", "nuclei"),
    required_inputs=("url",),
    mitre_technique="T1190", cwe_id="CWE-89",
))
_reg(AttackVector(
    id="api_rate_limit_bypass", name="API Rate Limit Bypass", category="api",
    description="Circumvent API rate limiting via header manipulation",
    severity="medium",
    detection_methods=("active_scan",),
    required_tools=("nuclei",),
    mitre_technique="T1499", cwe_id="CWE-770",
))
_reg(AttackVector(
    id="api_key_exposure", name="API Key Exposure", category="api",
    description="Discover exposed API keys in responses or JS files",
    severity="high",
    detection_methods=("passive_analysis", "crawling"),
    required_tools=("nuclei", "web_interact"),
    mitre_technique="T1552", cwe_id="CWE-200",
))

# ═══════════════════════════════════════════════════════════════════════
#  CATEGORY 6: LOGIC
# ═══════════════════════════════════════════════════════════════════════

_reg(AttackVector(
    id="parameter_tampering", name="Parameter Tampering", category="logic",
    description="Modify hidden/client-side parameters to bypass logic",
    severity="medium",
    detection_methods=("active_scan", "fuzzing"),
    required_tools=("web_interact", "nuclei"),
    mitre_technique="T1565", cwe_id="CWE-472",
))
_reg(AttackVector(
    id="workflow_bypass", name="Workflow Bypass", category="logic",
    description="Skip required steps in multi-step workflows",
    severity="high",
    detection_methods=("active_scan",),
    required_tools=("web_interact",),
    mitre_technique="T1078", cwe_id="CWE-841",
))
_reg(AttackVector(
    id="race_condition", name="Race Condition", category="logic",
    description="Exploit TOCTOU or concurrent request handling",
    severity="high",
    detection_methods=("active_scan",),
    required_tools=("custom_poc",),
    mitre_technique="T1068", cwe_id="CWE-362",
))
_reg(AttackVector(
    id="business_logic_flaw", name="Business Logic Flaw", category="logic",
    description="Exploit application-specific logic errors",
    severity="high",
    detection_methods=("active_scan",),
    required_tools=("web_interact", "custom_poc"),
    mitre_technique="T1190", cwe_id="CWE-840",
))
_reg(AttackVector(
    id="csrf", name="Cross-Site Request Forgery", category="logic",
    description="Force authenticated users to perform unwanted actions",
    severity="medium",
    detection_methods=("active_scan",),
    required_tools=("nuclei",),
    mitre_technique="T1185", cwe_id="CWE-352",
))

# ═══════════════════════════════════════════════════════════════════════
#  CATEGORY 7: INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════

_reg(AttackVector(
    id="ssrf", name="Server-Side Request Forgery", category="infrastructure",
    description="Force server to make requests to internal/external resources",
    severity="critical",
    detection_methods=("active_scan", "fuzzing"),
    required_tools=("nuclei",),
    mitre_technique="T1190", cwe_id="CWE-918",
))
_reg(AttackVector(
    id="open_redirect", name="Open Redirect", category="infrastructure",
    description="Redirect users to attacker-controlled URLs",
    severity="medium",
    detection_methods=("active_scan",),
    required_tools=("nuclei",),
    mitre_technique="T1204", cwe_id="CWE-601",
))
_reg(AttackVector(
    id="cors_misconfig", name="CORS Misconfiguration", category="infrastructure",
    description="Overly permissive CORS allowing credential theft",
    severity="high",
    detection_methods=("active_scan",),
    required_tools=("cors_scanner", "nuclei"),
    mitre_technique="T1557", cwe_id="CWE-942",
))
_reg(AttackVector(
    id="host_header_injection", name="Host Header Injection", category="infrastructure",
    description="Manipulate host headers for cache poisoning or SSRF",
    severity="medium",
    detection_methods=("active_scan",),
    required_tools=("nuclei",),
    mitre_technique="T1557", cwe_id="CWE-644",
))
_reg(AttackVector(
    id="dns_rebinding", name="DNS Rebinding", category="infrastructure",
    description="Bypass same-origin via DNS TTL manipulation",
    severity="high",
    detection_methods=("active_scan",),
    required_tools=("nuclei",),
    mitre_technique="T1557", cwe_id="CWE-350",
))
_reg(AttackVector(
    id="websocket_hijacking", name="WebSocket Hijacking", category="infrastructure",
    description="Hijack WebSocket connections via CSWSH",
    severity="high",
    detection_methods=("active_scan",),
    required_tools=("nuclei", "web_interact"),
    mitre_technique="T1557", cwe_id="CWE-1385",
))

# ═══════════════════════════════════════════════════════════════════════
#  CATEGORY 8: CACHE & TRANSPORT
# ═══════════════════════════════════════════════════════════════════════

_reg(AttackVector(
    id="http_request_smuggling", name="HTTP Request Smuggling", category="cache_transport",
    description="Desync front-end/back-end via CL.TE or TE.CL",
    severity="high",
    detection_methods=("active_scan",),
    required_tools=("nuclei",),
    mitre_technique="T1557", cwe_id="CWE-444",
))
_reg(AttackVector(
    id="cache_poisoning", name="Cache Poisoning", category="cache_transport",
    description="Poison web cache to serve malicious content",
    severity="high",
    detection_methods=("active_scan",),
    required_tools=("nuclei",),
    mitre_technique="T1557", cwe_id="CWE-349",
))
_reg(AttackVector(
    id="cache_deception", name="Web Cache Deception", category="cache_transport",
    description="Trick cache into storing sensitive responses",
    severity="medium",
    detection_methods=("active_scan",),
    required_tools=("nuclei",),
    mitre_technique="T1557", cwe_id="CWE-524",
))
_reg(AttackVector(
    id="tls_downgrade", name="TLS Downgrade", category="cache_transport",
    description="Force protocol downgrade to weaker ciphers",
    severity="medium",
    detection_methods=("active_scan",),
    required_tools=("nmap_svc", "nikto"),
    required_inputs=("domain",),
    mitre_technique="T1557", cwe_id="CWE-757",
))

# ═══════════════════════════════════════════════════════════════════════
#  CATEGORY 9: INFO DISCLOSURE
# ═══════════════════════════════════════════════════════════════════════

_reg(AttackVector(
    id="debug_endpoints", name="Debug Endpoints Exposed", category="info_disclosure",
    description="Find exposed debug/admin endpoints",
    severity="high",
    detection_methods=("fuzzing", "passive_analysis"),
    required_tools=("ffuf", "nuclei", "nikto"),
    mitre_technique="T1592", cwe_id="CWE-215",
))
_reg(AttackVector(
    id="verbose_errors", name="Verbose Error Messages", category="info_disclosure",
    description="Stack traces or debug info in error responses",
    severity="medium",
    detection_methods=("passive_analysis",),
    required_tools=("nuclei", "nikto"),
    mitre_technique="T1592", cwe_id="CWE-209",
))
_reg(AttackVector(
    id="sensitive_data_exposure", name="Sensitive Data Exposure", category="info_disclosure",
    description="Credentials, tokens, or PII in responses/files",
    severity="high",
    detection_methods=("passive_analysis", "crawling"),
    required_tools=("nuclei", "web_interact"),
    mitre_technique="T1552", cwe_id="CWE-200",
    owasp_category="A02:2021 Cryptographic Failures",
))
_reg(AttackVector(
    id="directory_listing", name="Directory Listing", category="info_disclosure",
    description="Web server directory listing enabled",
    severity="low",
    detection_methods=("active_scan",),
    required_tools=("nuclei", "nikto"),
    mitre_technique="T1083", cwe_id="CWE-548",
))
_reg(AttackVector(
    id="js_endpoint_discovery", name="JS Endpoint Discovery", category="info_disclosure",
    description="Extract API endpoints from JavaScript files",
    severity="info",
    detection_methods=("crawling", "passive_analysis"),
    required_tools=("web_interact",),
    mitre_technique="T1592", cwe_id="CWE-200",
))
_reg(AttackVector(
    id="git_exposure", name="Git Repository Exposure", category="info_disclosure",
    description="Exposed .git directory leaking source code",
    severity="critical",
    detection_methods=("active_scan",),
    required_tools=("nuclei", "ffuf"),
    mitre_technique="T1552", cwe_id="CWE-538",
))
_reg(AttackVector(
    id="stack_traces", name="Stack Trace Disclosure", category="info_disclosure",
    description="Full stack traces revealing internal architecture",
    severity="medium",
    detection_methods=("passive_analysis",),
    required_tools=("nuclei",),
    mitre_technique="T1592", cwe_id="CWE-209",
))
_reg(AttackVector(
    id="security_headers_missing", name="Missing Security Headers", category="info_disclosure",
    description="Missing HSTS, CSP, X-Frame-Options, etc.",
    severity="low",
    detection_methods=("passive_analysis",),
    required_tools=("header_audit_tool", "nikto"),
    mitre_technique="T1189", cwe_id="CWE-693",
))

# ═══════════════════════════════════════════════════════════════════════
#  CATEGORY 10: SUPPLY CHAIN
# ═══════════════════════════════════════════════════════════════════════

_reg(AttackVector(
    id="subdomain_takeover", name="Subdomain Takeover", category="supply_chain",
    description="Claim dangling DNS records pointing to deprovisioned services",
    severity="high",
    detection_methods=("active_scan",),
    required_tools=("subfinder", "nuclei"),
    required_inputs=("domain",),
    mitre_technique="T1584", cwe_id="CWE-284",
))
_reg(AttackVector(
    id="vulnerable_dependencies", name="Vulnerable Dependencies", category="supply_chain",
    description="Known CVEs in third-party libraries and frameworks",
    severity="high",
    detection_methods=("passive_analysis",),
    required_tools=("nuclei",),
    mitre_technique="T1195", cwe_id="CWE-1104",
    owasp_category="A06:2021 Vulnerable Components",
))
_reg(AttackVector(
    id="dependency_confusion", name="Dependency Confusion", category="supply_chain",
    description="Package manager namespace confusion attacks",
    severity="critical",
    detection_methods=("passive_analysis",),
    required_tools=("nuclei",),
    mitre_technique="T1195.001", cwe_id="CWE-427",
))
_reg(AttackVector(
    id="outdated_software", name="Outdated Software", category="supply_chain",
    description="Running known-vulnerable versions of server software",
    severity="medium",
    detection_methods=("passive_analysis",),
    required_tools=("nmap_svc", "nuclei", "nikto"),
    mitre_technique="T1195", cwe_id="CWE-1104",
))


# ═══════════════════════════════════════════════════════════════════════
#  REGISTRY API
# ═══════════════════════════════════════════════════════════════════════

def get_vector(vector_id: str) -> AttackVector | None:
    """Get a single attack vector by ID."""
    return ATTACK_VECTOR_REGISTRY.get(vector_id)


def get_vectors_by_category(category: str) -> list[AttackVector]:
    """Get all vectors in a category."""
    return [v for v in ATTACK_VECTOR_REGISTRY.values() if v.category == category]


def get_all_categories() -> list[str]:
    """Get all unique categories."""
    return sorted({v.category for v in ATTACK_VECTOR_REGISTRY.values()})


def get_all_vector_ids() -> list[str]:
    """Get all registered vector IDs."""
    return list(ATTACK_VECTOR_REGISTRY.keys())


def get_vectors_for_scan_profile(
    scan_type: str,
    target_type: str = "web_app",
    enabled_vectors: list[str] | None = None,
) -> list[AttackVector]:
    """Select attack vectors appropriate for a scan profile.

    Args:
        scan_type: recon, vuln, or full
        target_type: web_app, api, network, domain
        enabled_vectors: optional explicit list; if None, auto-select
    """
    if enabled_vectors:
        return [ATTACK_VECTOR_REGISTRY[v] for v in enabled_vectors if v in ATTACK_VECTOR_REGISTRY]

    # Auto-select based on scan type
    all_vectors = list(ATTACK_VECTOR_REGISTRY.values())

    if scan_type == "recon":
        recon_categories = {"info_disclosure", "supply_chain"}
        return [v for v in all_vectors if v.category in recon_categories]

    if scan_type == "vuln":
        exclude = {"logic"}  # Logic bugs need auth context, skip in vuln scan
        return [v for v in all_vectors if v.category not in exclude]

    # full scan — everything
    return all_vectors


def build_tool_list_from_vectors(vectors: list[AttackVector]) -> list[str]:
    """Deduplicate and return ordered tool list from selected vectors."""
    # Priority order for tool categories
    category_order = {
        "recon": 0, "enum": 1, "vuln_scan": 2,
        "verification": 3, "ai_analysis": 4, "report_gen": 5,
    }
    tools: set[str] = set()
    for v in vectors:
        tools.update(v.required_tools)
        tools.update(v.optional_tools)
    return sorted(tools)


def get_required_inputs_for_vectors(vectors: list[AttackVector]) -> set[InputType]:
    """Determine all required input types for a set of vectors."""
    inputs: set[InputType] = set()
    for v in vectors:
        inputs.update(v.required_inputs)
    return inputs


def get_coverage_summary() -> dict[str, Any]:
    """Summary statistics for the attack vector registry."""
    categories: dict[str, int] = {}
    severities: dict[str, int] = {}
    for v in ATTACK_VECTOR_REGISTRY.values():
        categories[v.category] = categories.get(v.category, 0) + 1
        severities[v.severity] = severities.get(v.severity, 0) + 1

    return {
        "total_vectors": len(ATTACK_VECTOR_REGISTRY),
        "categories": categories,
        "severities": severities,
        "total_tools_referenced": len(build_tool_list_from_vectors(list(ATTACK_VECTOR_REGISTRY.values()))),
    }
