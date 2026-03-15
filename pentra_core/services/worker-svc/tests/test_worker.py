"""MOD-05 Worker System tests — validates tool registry, container runner,
artifact normalization, event contracts, and worker service composition.

Run:
    cd pentra_core/services/worker-svc
    python -m pytest tests/test_worker.py -v
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


# ═══════════════════════════════════════════════════════════════════
# 1. Tool Registry — YAML loading
# ═══════════════════════════════════════════════════════════════════


def test_registry_loads_all_tools():
    """All YAML tool specs must be loaded."""
    from app.tools.tool_registry import get_all_tools
    tools = get_all_tools()
    assert len(tools) >= 13, f"Expected >= 13 tools, got {len(tools)}"


def test_registry_has_expected_tools():
    """Every tool referenced in DAGBuilder must exist in the registry."""
    from app.tools.tool_registry import get_tool

    expected = [
        "scope_check", "subfinder", "amass", "nmap_discovery",
        "httpx_probe", "web_interact", "nmap_svc", "ffuf", "nuclei", "zap", "sqlmap",
        "metasploit", "ai_triage", "report_gen",
    ]
    for name in expected:
        tool = get_tool(name)
        assert tool is not None, f"Tool '{name}' not found in registry"
        assert tool.name == name


def test_registry_tool_has_required_fields():
    """Every tool must have name, image, command, output_parser, artifact_type."""
    from app.tools.tool_registry import get_all_tools

    for name, tool in get_all_tools().items():
        assert tool.name, f"Tool {name} missing name"
        assert tool.image, f"Tool {name} missing image"
        assert len(tool.command) > 0, f"Tool {name} missing command"
        assert tool.output_parser, f"Tool {name} missing output_parser"
        assert tool.artifact_type, f"Tool {name} missing artifact_type"
        assert tool.default_timeout > 0, f"Tool {name} has invalid timeout"


def test_registry_worker_families():
    """All 5 worker families must be represented."""
    from app.tools.tool_registry import get_all_tools

    families = {t.worker_family for t in get_all_tools().values()}
    for expected in ["recon", "network", "web", "vuln", "exploit"]:
        assert expected in families, f"Family '{expected}' not found"


def test_registry_get_tools_for_family():
    """get_tools_for_family must return correct subset."""
    from app.tools.tool_registry import get_tools_for_family

    recon_tools = get_tools_for_family("recon")
    assert len(recon_tools) >= 3  # scope_check, subfinder, amass (+ ai_triage, report_gen)
    assert all(t.worker_family == "recon" for t in recon_tools)


def test_registry_command_rendering():
    """render_command must interpolate {target} and {output_dir}."""
    from app.tools.tool_registry import get_tool, render_command

    tool = get_tool("subfinder")
    assert tool is not None
    cmd = render_command(tool, target="example.com", output_dir="/work/out")
    assert "example.com" in cmd[2]  # -d {target}
    assert "/work/out" in cmd[4]    # -o {output_dir}/subdomains.json


def test_registry_command_rendering_with_profile_context():
    """Profile context placeholders should render into tool commands."""
    from app.tools.tool_registry import get_tool, render_command

    tool = get_tool("httpx_probe")
    assert tool is not None
    cmd = render_command(
        tool,
        target="https://example.com",
        output_dir="/work/out",
        context={
            "http_rate_limit": 77,
            "httpx_targets_file": "/work/input/httpx_targets.txt",
        },
    )
    assert "/work/input/httpx_targets.txt" in cmd
    assert "77" in cmd


# ═══════════════════════════════════════════════════════════════════
# 2. Container Runner — simulation mode
# ═══════════════════════════════════════════════════════════════════


def test_container_result_dataclass():
    """ContainerResult must carry exit_code, stdout, stderr, output_dir."""
    from app.engine.container_runner import ContainerResult

    result = ContainerResult(
        exit_code=0, stdout="ok", stderr="", output_dir="/tmp/out",
    )
    assert result.exit_code == 0
    assert result.timed_out is False


def test_container_runner_exists():
    from app.engine.container_runner import ContainerRunner
    runner = ContainerRunner()
    assert runner is not None


def test_container_runner_local_only_policy_blocks_remote_live_targets():
    from app.engine.container_runner import ContainerRunner

    runner = ContainerRunner()
    assert runner._target_allowed_for_live(
        target="http://127.0.0.1:8088",
        scan_config={"execution": {"target_policy": "local_only"}},
    ) is True
    assert runner._target_allowed_for_live(
        target="https://example.com",
        scan_config={"execution": {"target_policy": "local_only"}},
    ) is False


def test_container_runner_prepares_phase3_runtime_inputs():
    from app.engine.container_runner import ContainerRunner

    runner = ContainerRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        input_dir = Path(tmpdir)
        config = {
            "selected_checks": {
                "http_probe_paths": ["/", "/graphql"],
                "content_paths": ["graphql", "openapi.json", "api/v1/auth/login"],
            }
        }

        runner._prepare_runtime_inputs(
            tool_name="httpx_probe",
            target="http://127.0.0.1:8088",
            input_dir=input_dir,
            scan_config=config,
        )
        runner._prepare_runtime_inputs(
            tool_name="ffuf",
            target="http://127.0.0.1:8088",
            input_dir=input_dir,
            scan_config=config,
        )
        runner._prepare_runtime_inputs(
            tool_name="nuclei",
            target="http://127.0.0.1:8088",
            input_dir=input_dir,
            scan_config=config,
        )

        assert (input_dir / "httpx_targets.txt").exists()
        assert "http://127.0.0.1:8088/graphql" in (input_dir / "httpx_targets.txt").read_text()
        assert (input_dir / "ffuf_wordlist.txt").exists()
        assert "api/v1/auth/login" in (input_dir / "ffuf_wordlist.txt").read_text()
        assert (input_dir / "nuclei_targets.txt").read_text().strip() == "http://127.0.0.1:8088"
        assert (input_dir / "nuclei-templates" / "sqli-login.yaml").exists()


# ═══════════════════════════════════════════════════════════════════
# 3. Artifact Handler — normalization
# ═══════════════════════════════════════════════════════════════════


def test_normalize_json_output():
    """normalize_output must parse JSON files from output directory."""
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write mock JSON output
        output = [{"host": "example.com", "ip": "93.184.216.34"}]
        Path(tmpdir, "results.json").write_text(json.dumps(output))

        artifact = normalize_output(
            output_dir=tmpdir,
            output_parser="json",
            tool_name="subfinder",
            artifact_type="subdomains",
            scan_id="scan-1",
            node_id="node-1",
            tenant_id="tenant-1",
            exit_code=0,
            duration_ms=1000,
        )

        assert artifact["tool"] == "subfinder"
        assert artifact["artifact_type"] == "subdomains"
        assert artifact["item_count"] == 1
        assert len(artifact["items"]) == 1
        assert artifact["items"][0]["host"] == "example.com"
        assert artifact["metadata"]["exit_code"] == 0


def test_normalize_jsonl_output():
    """normalize_output must handle JSONL (one object per line)."""
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        lines = '{"host":"a.com"}\n{"host":"b.com"}\n'
        Path(tmpdir, "out.json").write_text(lines)

        artifact = normalize_output(
            output_dir=tmpdir,
            output_parser="json",
            tool_name="nuclei",
            artifact_type="vulnerabilities",
            scan_id="s", node_id="n", tenant_id="t",
            exit_code=0,
        )
        assert artifact["item_count"] == 2


def test_normalize_nmap_xml():
    """normalize_output must parse Nmap XML into host/port records."""
    from app.engine.artifact_handler import normalize_output

    nmap_xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="10.0.0.1"/>
        <status state="up"/>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" version="2.4"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "scan.xml").write_text(nmap_xml)

        artifact = normalize_output(
            output_dir=tmpdir,
            output_parser="xml_nmap",
            tool_name="nmap_discovery",
            artifact_type="hosts",
            scan_id="s", node_id="n", tenant_id="t",
            exit_code=0,
        )
        assert artifact["item_count"] == 1
        assert artifact["items"][0]["host"] == "10.0.0.1"
        assert artifact["items"][0]["ports"][0]["port"] == 80


def test_normalize_raw_output():
    """normalize_output must wrap raw files as blobs."""
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "results.txt").write_text("some raw output")

        artifact = normalize_output(
            output_dir=tmpdir,
            output_parser="raw",
            tool_name="sqlmap",
            artifact_type="vulnerabilities",
            scan_id="s", node_id="n", tenant_id="t",
            exit_code=0,
        )
        assert artifact["item_count"] == 1
        assert "content" in artifact["items"][0]


def test_normalize_sqlmap_live_output_extracts_clean_endpoint_and_evidence():
    """sqlmap raw output should normalize into a clean finding, not a raw csv-ish target."""
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        log_dir = Path(tmpdir) / "127.0.0.1"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "target.txt").write_text(
            "http://127.0.0.1:8088/api/v1/auth/login?username=admin&password=admin123 (GET)"
        )
        (log_dir / "log").write_text(
            "\n".join(
                [
                    "sqlmap identified the following injection point(s) with a total of 49 HTTP(s) requests:",
                    "---",
                    "Parameter: username (GET)",
                    "    Type: boolean-based blind",
                    "    Title: AND boolean-based blind - WHERE or HAVING clause",
                    "    Payload: username=admin' AND 7485=7485-- guCW&password=admin123",
                    "",
                    "    Type: time-based blind",
                    "    Title: SQLite > 2.0 AND time-based blind (heavy query)",
                    "    Payload: username=admin' AND 3679=LIKE(CHAR(65,66,67))-- dwmi&password=admin123",
                    "",
                    "    Type: UNION query",
                    "    Title: Generic UNION query (NULL) - 2 columns",
                    "    Payload: username=-3854' UNION ALL SELECT 1,NULL-- LeMH&password=admin123",
                    "---",
                    "back-end DBMS: SQLite",
                ]
            )
        )

        artifact = normalize_output(
            output_dir=str(log_dir.parent),
            output_parser="raw",
            tool_name="sqlmap",
            artifact_type="vulnerabilities",
            scan_id="s",
            node_id="n",
            tenant_id="t",
            exit_code=0,
        )

        assert artifact["item_count"] == 1
        item = artifact["items"][0]
        assert item["endpoint"] == "http://127.0.0.1:8088/api/v1/auth/login"
        assert item["route_group"] == "/api/v1/auth/login"
        assert item["request"] == (
            "GET http://127.0.0.1:8088/api/v1/auth/login?username=admin&password=admin123"
        )
        assert item["payload"].startswith("username=admin'")
        assert "SQLite" in item["description"]
        evidence_types = {entry["evidence_type"] for entry in artifact["evidence"]}
        assert {"request", "payload", "exploit_result"} <= evidence_types


def test_normalize_sqlmap_verify_output_marks_finding_verified():
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        log_dir = Path(tmpdir) / "127.0.0.1"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "target.txt").write_text(
            "http://127.0.0.1:8088/api/v1/auth/login?username=admin&password=admin123 (GET)"
        )
        (log_dir / "log").write_text(
            "\n".join(
                [
                    "sqlmap identified the following injection point(s):",
                    "Parameter: username (GET)",
                    "    Type: boolean-based blind",
                    "    Payload: username=admin' AND 1=1-- test&password=admin123",
                    "back-end DBMS: SQLite",
                ]
            )
        )

        artifact = normalize_output(
            output_dir=str(log_dir.parent),
            output_parser="raw",
            tool_name="sqlmap_verify",
            artifact_type="database_access",
            scan_id="s",
            node_id="n",
            tenant_id="t",
            exit_code=0,
        )

        assert artifact["artifact_type"] == "database_access"
        assert artifact["findings"][0]["source_type"] == "exploit_verify"
        classification = artifact["findings"][0]["evidence"]["classification"]
        assert classification["verification_state"] == "verified"
        assert classification["verified"] is True


def test_store_artifact():
    """store_artifact must write JSON and return a storage_ref path."""
    from app.engine.artifact_handler import store_artifact
    import app.engine.artifact_handler as ah

    with tempfile.TemporaryDirectory() as tmpdir:
        # Temporarily redirect artifact store
        old = ah.ARTIFACT_STORE
        ah.ARTIFACT_STORE = tmpdir

        try:
            artifact = {
                "tool": "nuclei",
                "artifact_type": "vulnerabilities",
                "item_count": 0,
                "items": [],
                "metadata": {"exit_code": 0},
            }
            ref = store_artifact(
                artifact,
                scan_id="scan-1",
                node_id="node-1",
                tenant_id="tenant-1",
                tool_name="nuclei",
            )
            assert ref.startswith("artifacts/")
            assert "nuclei.json" in ref

            # Verify file was written
            full_path = Path(tmpdir) / "tenant-1" / "scan-1" / "node-1" / "nuclei.json"
            assert full_path.exists()
        finally:
            ah.ARTIFACT_STORE = old


def test_unified_artifact_schema():
    """Normalized artifact must contain all required fields."""
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "empty.json").write_text("[]")

        artifact = normalize_output(
            output_dir=tmpdir,
            output_parser="json",
            tool_name="test_tool",
            artifact_type="test_type",
            scan_id="s", node_id="n", tenant_id="t",
            exit_code=0, duration_ms=500,
        )

        # Schema validation
        assert "tool" in artifact
        assert "artifact_type" in artifact
        assert "scan_id" in artifact
        assert "node_id" in artifact
        assert "tenant_id" in artifact
        assert "timestamp" in artifact
        assert "item_count" in artifact
        assert "items" in artifact
        assert "metadata" in artifact
        assert "exit_code" in artifact["metadata"]
        assert "duration_ms" in artifact["metadata"]
        assert "raw_size_bytes" in artifact["metadata"]


def test_normalize_httpx_output_enriches_endpoint_metadata():
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "httpx.json").write_text(
            json.dumps(
                [
                    {
                        "url": "https://example.com/graphql",
                        "status_code": 200,
                        "content_length": 612,
                        "title": "GraphQL API",
                        "webserver": "nginx",
                        "tech": ["GraphQL", "Apollo Server"],
                    }
                ]
            )
        )

        artifact = normalize_output(
            output_dir=tmpdir,
            output_parser="json",
            tool_name="httpx_probe",
            artifact_type="endpoints",
            scan_id="scan-1",
            node_id="node-1",
            tenant_id="tenant-1",
            exit_code=0,
            scan_config={
                "scope": {
                    "allowed_hosts": ["example.com"],
                    "include_subdomains": True,
                    "max_endpoints": 10,
                }
            },
        )

        assert artifact["item_count"] == 1
        assert artifact["items"][0]["surface"] == "api"
        assert artifact["items"][0]["primary_technology"] == "GraphQL"
        assert artifact["summary"]["technology_counts"]["GraphQL"] >= 1


def test_normalize_web_interact_output_tracks_stateful_context_and_workflow_edges():
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "web_interactions.json").write_text(
            json.dumps(
                {
                    "pages": [
                        {
                            "url": "http://127.0.0.1:8088/login",
                            "title": "Pentra Login",
                            "status_code": 200,
                            "session_label": "unauthenticated",
                            "auth_state": "none",
                        },
                        {
                            "url": "http://127.0.0.1:8088/portal/dashboard",
                            "title": "Customer Dashboard",
                            "status_code": 200,
                            "session_label": "john",
                            "auth_state": "authenticated",
                            "requires_auth": True,
                            "source_url": "http://127.0.0.1:8088/login",
                        },
                    ],
                    "forms": [
                        {
                            "page_url": "http://127.0.0.1:8088/login",
                            "action_url": "http://127.0.0.1:8088/login",
                            "method": "POST",
                            "field_names": ["username", "password", "csrf_token"],
                            "hidden_field_names": ["csrf_token", "pentra_safe_replay"],
                            "has_csrf": True,
                            "safe_replay": True,
                            "session_label": "unauthenticated",
                        }
                    ],
                    "sessions": [
                        {
                            "session_label": "john",
                            "auth_state": "authenticated",
                            "cookie_names": ["pentra_session"],
                            "csrf_tokens": ["demo-csrf"],
                        }
                    ],
                    "workflows": [
                        {
                            "source_url": "http://127.0.0.1:8088/login",
                            "target_url": "http://127.0.0.1:8088/portal/dashboard",
                            "action": "login",
                            "session_label": "john",
                        }
                    ],
                    "replays": [
                        {
                            "request": "POST http://127.0.0.1:8088/login",
                            "target_url": "http://127.0.0.1:8088/login",
                            "session_label": "john",
                            "status_code": 200,
                        }
                    ],
                },
                indent=2,
            )
        )

        artifact = normalize_output(
            output_dir=tmpdir,
            output_parser="json",
            tool_name="web_interact",
            artifact_type="endpoints",
            scan_id="scan-1",
            node_id="node-1",
            tenant_id="tenant-1",
            exit_code=0,
            scan_config={
                "scope": {
                    "allowed_hosts": ["127.0.0.1"],
                    "max_endpoints": 20,
                }
            },
        )

        assert artifact["item_count"] >= 2
        assert artifact["summary"]["stateful_context"]["session_count"] == 1
        assert artifact["summary"]["stateful_context"]["form_count"] == 1
        assert artifact["summary"]["stateful_context"]["workflow_count"] == 1
        assert artifact["summary"]["stateful_context"]["replay_count"] == 1
        assert any(edge["edge_type"] == "login" for edge in artifact["relationships"])
        login_endpoint = next(item for item in artifact["items"] if item["url"].endswith("/login"))
        assert login_endpoint["has_csrf"] is True
        assert login_endpoint["interaction_kind"] == "form"


def test_normalize_custom_poc_preserves_explicit_stateful_vulnerability_type():
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "custom_poc.json").write_text(
            json.dumps(
                [
                    {
                        "title": "Authorization bypass confirmed via stateful replay",
                        "severity": "high",
                        "confidence": 80,
                        "target": "http://127.0.0.1:8088/portal/admin/users/2",
                        "endpoint": "http://127.0.0.1:8088/portal/admin/users/2",
                        "description": "Cross-session replay reached another user's record.",
                        "tool_source": "custom_poc",
                        "vulnerability_type": "auth_bypass",
                        "request": "GET /portal/admin/users/2",
                        "response": "HTTP/1.1 200 OK",
                        "payload": "cross_session",
                        "exploit_result": "unauthenticated_access_succeeded",
                        "surface": "web",
                        "route_group": "/portal/admin/users/{id}",
                        "exploitability": "high",
                    }
                ],
                indent=2,
            )
        )

        artifact = normalize_output(
            output_dir=tmpdir,
            output_parser="json",
            tool_name="custom_poc",
            artifact_type="vulnerabilities",
            scan_id="scan-1",
            node_id="node-1",
            tenant_id="tenant-1",
            exit_code=0,
            scan_config={
                "scope": {
                    "allowed_hosts": ["127.0.0.1"],
                    "max_endpoints": 20,
                }
            },
        )

        assert artifact["findings"][0]["vulnerability_type"] == "auth_bypass"


def test_parse_json_supports_pretty_printed_objects():
    from app.engine.artifact_handler import _parse_json

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "object.json").write_text(
            json.dumps({"pages": [{"url": "http://127.0.0.1:8088"}]}, indent=2)
        )

        items = _parse_json(Path(tmpdir))

        assert items == [{"pages": [{"url": "http://127.0.0.1:8088"}]}]


def test_normalize_vulnerabilities_applies_scope_limits_and_dedupes():
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "nuclei.json").write_text(
            json.dumps(
                [
                    {
                        "template-id": "pentra/sql-injection",
                        "matched-at": "https://example.com/api/v1/auth/login",
                        "info": {"name": "SQL Injection in Login Endpoint", "severity": "critical"},
                        "payload": "admin' OR '1'='1",
                    },
                    {
                        "template-id": "pentra/sql-injection-duplicate",
                        "matched-at": "https://example.com/api/v1/auth/login",
                        "info": {"name": "SQL Injection confirmed via sqlmap", "severity": "critical"},
                        "payload": "admin' OR '1'='1",
                    },
                    {
                        "template-id": "pentra/out-of-scope",
                        "matched-at": "https://evil.com/api/v1/auth/login",
                        "info": {"name": "Exposed OpenAPI Schema", "severity": "medium"},
                    },
                ]
            )
        )

        artifact = normalize_output(
            output_dir=tmpdir,
            output_parser="json",
            tool_name="nuclei",
            artifact_type="vulnerabilities",
            scan_id="scan-1",
            node_id="node-1",
            tenant_id="tenant-1",
            exit_code=0,
            scan_config={
                "scope": {
                    "allowed_hosts": ["example.com"],
                    "include_subdomains": True,
                    "max_endpoints": 10,
                }
            },
        )

        assert artifact["item_count"] == 1
        assert len(artifact["findings"]) == 1
        assert artifact["findings"][0]["exploitability"] == "high"
        assert artifact["metadata"]["guardrail_stats"]["filtered_out_of_scope"] == 1


# ═══════════════════════════════════════════════════════════════════
# 4. Event Emitter — payload contracts
# ═══════════════════════════════════════════════════════════════════


def test_event_emitter_exists():
    from app.events.event_emitter import EventEmitter
    assert EventEmitter is not None


def test_event_emitter_has_completed():
    assert hasattr(
        __import__("app.events.event_emitter", fromlist=["EventEmitter"]).EventEmitter,
        "emit_job_completed",
    )


def test_event_emitter_has_failed():
    assert hasattr(
        __import__("app.events.event_emitter", fromlist=["EventEmitter"]).EventEmitter,
        "emit_job_failed",
    )


def test_event_emitter_uses_correct_stream():
    from app.events.event_emitter import STREAM_JOB_EVENTS
    assert STREAM_JOB_EVENTS == "pentra:stream:job_events"


# ═══════════════════════════════════════════════════════════════════
# 5. Job Consumer — stream configuration
# ═══════════════════════════════════════════════════════════════════


def test_job_consumer_exists():
    from app.events.job_consumer import JobConsumer
    assert JobConsumer is not None


def test_job_consumer_stream_prefix():
    from app.events.job_consumer import _WORKER_STREAM_PREFIX
    assert _WORKER_STREAM_PREFIX == "pentra:stream:worker"


# ═══════════════════════════════════════════════════════════════════
# 6. Worker Service — composition
# ═══════════════════════════════════════════════════════════════════


def test_worker_service_exists():
    from app.services.worker_service import WorkerService
    assert WorkerService is not None


def test_worker_service_has_execute_job():
    from app.services.worker_service import WorkerService
    assert hasattr(WorkerService, "execute_job")


def test_worker_service_uses_all_components():
    """WorkerService must use ContainerRunner, EventEmitter, tool_registry."""
    import inspect
    from app.services.worker_service import WorkerService

    source = inspect.getsource(WorkerService)
    assert "ContainerRunner" in source
    assert "EventEmitter" in source
    assert "get_tool" in source
    assert "render_command" in source
    assert "normalize_output" in source
    assert "store_artifact" in source


def test_worker_service_derives_per_tool_targets():
    from app.services.worker_service import _command_target_for_tool

    config = {
        "targeting": {
            "host": "example.com",
            "base_url": "https://example.com",
        }
    }

    assert _command_target_for_tool(tool_name="subfinder", target="https://example.com", config=config) == "example.com"
    assert _command_target_for_tool(tool_name="nuclei", target="https://example.com", config=config) == "https://example.com"


# ═══════════════════════════════════════════════════════════════════
# 7. Main entrypoint — no FastAPI
# ═══════════════════════════════════════════════════════════════════


def test_main_has_no_fastapi():
    """main.py must NOT import FastAPI."""
    import inspect
    import app.main as main_mod

    source = inspect.getsource(main_mod)
    # Check import lines only — docstring mentions are fine
    import_lines = [l for l in source.splitlines() if l.strip().startswith(("import ", "from "))]
    for line in import_lines:
        assert "fastapi" not in line.lower(), f"FastAPI imported: {line}"


def test_main_uses_async_loop():
    """main.py must use asyncio.run."""
    import inspect
    import app.main as main_mod

    source = inspect.getsource(main_mod)
    assert "asyncio.run" in source


def test_main_uses_job_consumer():
    """main.py must use JobConsumer."""
    import inspect
    import app.main as main_mod

    source = inspect.getsource(main_mod)
    assert "JobConsumer" in source


# ═══════════════════════════════════════════════════════════════════
# 8. Container Runner — security
# ═══════════════════════════════════════════════════════════════════


def test_exploit_family_no_network():
    """Exploit family must get network_mode='none'."""
    from app.engine.container_runner import _FAMILY_NETWORK
    assert _FAMILY_NETWORK.get("exploit") == "none"


def test_container_runner_has_cleanup():
    """ContainerRunner must have cleanup_job method."""
    from app.engine.container_runner import ContainerRunner
    assert hasattr(ContainerRunner, "cleanup_job")


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
