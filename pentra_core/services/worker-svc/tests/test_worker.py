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
        "dalfox", "graphql_cop", "jwt_tool", "cors_scanner",
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


def test_graphql_cop_command_renders_graphql_target_url():
    """graphql_cop should emit JSON to stdout while targeting the exact GraphQL path."""
    from app.tools.tool_registry import get_tool, render_command

    tool = get_tool("graphql_cop")
    assert tool is not None
    cmd = render_command(
        tool,
        target="https://example.com",
        output_dir="/work/out",
        context={"graphql_target_url": "https://example.com/api/graphql"},
    )
    assert cmd == ["-t", "https://example.com/api/graphql", "-o", "json"]


def test_container_runner_materializes_graphql_cop_stdout(tmp_path):
    from app.engine.container_runner import ContainerRunner

    runner = ContainerRunner()
    runner._materialize_graphql_cop_output(
        output_dir=str(tmp_path),
        stdout="http://example.test/graphql does not seem to be running GraphQL.\n[]\n",
    )

    output_file = tmp_path / "graphql_cop.json"
    assert output_file.exists()
    assert output_file.read_text().strip() == "[]"


def test_tool_execution_class_audit_matches_registry() -> None:
    from app.tools.tool_registry import get_all_tools
    from pentra_common.execution_truth import classify_tool_execution

    native_expected = {"scope_check", "custom_poc", "web_interact"}
    for tool_name in get_all_tools():
        expected = "pentra_native" if tool_name in native_expected else "external_tool"
        assert classify_tool_execution(tool_name) == expected

    assert classify_tool_execution("graphql_cop") == "external_tool"


def test_container_runner_routes_graphql_cop_through_real_tool_path(monkeypatch, tmp_path):
    import asyncio

    from app.engine import container_runner as container_runner_module
    from app.engine.container_runner import ContainerResult, ContainerRunner

    runner = ContainerRunner()
    monkeypatch.setattr(container_runner_module, "WORK_DIR_BASE", str(tmp_path))

    async def _fake_get_docker(*, execution_mode: str):
        assert execution_mode == "controlled_live_scoped"
        return object()

    async def _fake_run_docker(**kwargs):
        assert kwargs["tool_name"] == "graphql_cop"
        assert kwargs["command"] == ["-t", "https://example.com/api/graphql", "-o", "json"]
        return ContainerResult(
            exit_code=0,
            stdout="[]\n",
            stderr="",
            output_dir=kwargs["output_dir"],
            execution_mode=kwargs["execution_mode"],
            execution_provenance="live",
            execution_class="external_tool",
        )

    async def _unexpected_probe(**_kwargs):
        raise AssertionError("graphql_cop should use the real external tool path")

    monkeypatch.setattr(runner, "_get_docker", _fake_get_docker)
    monkeypatch.setattr(runner, "_run_docker", _fake_run_docker)
    monkeypatch.setattr(runner, "_run_graphql_cop_probe", _unexpected_probe, raising=False)

    result = asyncio.run(
        runner.run(
            image="dolevf/graphql-cop:latest",
            command=["-t", "https://example.com/api/graphql", "-o", "json"],
            working_dir="/app",
            entrypoint=None,
            tool_name="graphql_cop",
            target="https://example.com",
            job_id=uuid.uuid4(),
            worker_family="web",
            timeout=300,
            env_vars={},
            input_refs={},
            scan_config={
                "execution": {
                    "allowed_live_tools": ["graphql_cop"],
                    "mode": "controlled_live_scoped",
                    "target_policy": "in_scope",
                },
                "scope": {"allowed_hosts": ["example.com"]},
            },
        )
    )

    assert result.exit_code == 0
    assert result.execution_class == "external_tool"


def test_container_runner_run_keeps_graphql_cop_out_of_native_dispatch() -> None:
    import inspect

    from app.engine.container_runner import ContainerRunner

    source = inspect.getsource(ContainerRunner.run)
    assert 'if tool_name == "graphql_cop"' not in source


def test_worker_service_execution_log_artifacts_include_replay_session() -> None:
    from pentra_common.storage.artifacts import read_json_artifact

    from app.services.worker_service import WorkerService

    worker = WorkerService(redis=object())  # type: ignore[arg-type]
    refs = worker._store_execution_log_artifacts(
        scan_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        node_id=uuid.uuid4(),
        tool_name="graphql_cop",
        execution_class="external_tool",
        policy_state="auto_live",
        command=["graphql-cop", "-t", "http://127.0.0.1:8088/graphql", "-o", "json"],
        stdout='[{"name":"GraphQL introspection enabled","severity":"medium"}]\n',
        stderr="",
    )

    payload = read_json_artifact(refs["session_artifact_ref"])

    assert payload["tool"] == "graphql_cop"
    assert payload["execution_class"] == "external_tool"
    assert payload["policy_state"] == "auto_live"
    assert payload["runtime_stage"] == "completed"
    assert payload["stream_complete"] is True
    assert payload["frames"][0]["channel"] == "command"
    assert "http://127.0.0.1:8088/graphql" in payload["frames"][0]["chunk_text"]
    assert any(frame["channel"] == "stdout" for frame in payload["frames"])


def test_worker_service_live_session_tracking_persists_runtime_stages() -> None:
    from pentra_common.storage.artifacts import read_json_artifact

    from app.services.worker_service import WorkerService

    worker = WorkerService(redis=object())  # type: ignore[arg-type]
    scan_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    node_id = uuid.uuid4()
    started_at = "2026-03-28T00:00:00+00:00"

    live_state = worker._start_live_execution_tracking(
        scan_id=scan_id,
        tenant_id=tenant_id,
        node_id=node_id,
        tool_name="httpx_probe",
        execution_class="external_tool",
        policy_state="auto_live",
        command=["httpx", "-l", "/work/input/httpx_targets.txt", "-json"],
        image="projectdiscovery/httpx:latest",
        entrypoint=[],
        working_dir="/work/output",
        started_at=started_at,
    )

    session_ref = live_state["refs"]["session_artifact_ref"]
    payload = read_json_artifact(session_ref)
    assert payload["runtime_stage"] == "command_resolved"
    assert payload["stream_complete"] is False
    assert payload["last_chunk_at"] == started_at

    worker._append_live_execution_chunk(
        tool_name="httpx_probe",
        execution_class="external_tool",
        policy_state="auto_live",
        live_state=live_state,
        started_at=started_at,
        channel="stdout",
        chunk_text="http://example.com [200]\n",
        timestamp="2026-03-28T00:00:01+00:00",
    )

    payload = read_json_artifact(session_ref)
    assert payload["runtime_stage"] == "streaming"
    assert payload["stream_complete"] is False
    assert payload["last_chunk_at"] == "2026-03-28T00:00:01+00:00"
    assert any(frame["channel"] == "stdout" for frame in payload["frames"])

    worker._finalize_live_execution_tracking(
        tool_name="httpx_probe",
        execution_class="external_tool",
        policy_state="auto_live",
        live_state=live_state,
        started_at=started_at,
        completed_at="2026-03-28T00:00:03+00:00",
        status="completed",
        exit_code=0,
    )

    payload = read_json_artifact(session_ref)
    assert payload["runtime_stage"] == "completed"
    assert payload["stream_complete"] is True
    assert payload["last_chunk_at"] == "2026-03-28T00:00:01+00:00"


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


def test_web_interact_discovery_normalization_preserves_same_origin_spa_hash_routes():
    from app.engine.web_interaction_runner import _normalize_discovery_url

    assert _normalize_discovery_url("http://127.0.0.1:3001", "/#/contact") == "http://127.0.0.1:3001/#/contact"
    assert (
        _normalize_discovery_url("http://127.0.0.1:3001", "http://127.0.0.1:3001/#/search?q=test")
        == "http://127.0.0.1:3001/#/search?q=test"
    )
    assert _normalize_discovery_url("http://127.0.0.1:3001", "#section") == "http://127.0.0.1:3001/"


def test_web_interact_extracts_spa_hash_routes_from_script_content():
    from app.engine.web_interaction_runner import _extract_script_discovery_urls

    urls = _extract_script_discovery_urls(
        "http://127.0.0.1:3001",
        """
        const routes = [
          { path: 'search' },
          { path: 'contact' },
          { path: '**', redirectTo: 'login' }
        ];
        fetch('/api/Users');
        """,
    )

    assert "http://127.0.0.1:3001/#/search" in urls
    assert "http://127.0.0.1:3001/#/contact" in urls
    assert "http://127.0.0.1:3001/#/login" in urls
    assert "http://127.0.0.1:3001/api/Users" in urls


def test_web_interact_parser_collects_router_link_routes():
    from app.engine.web_interaction_runner import _DiscoveryParser

    parser = _DiscoveryParser()
    parser.feed(
        """
        <nav>
          <button routerLink="/profile">Profile</button>
          <a ng-reflect-router-link="/contact">Contact</a>
        </nav>
        """
    )

    assert "/#/profile" in parser.links
    assert "/#/contact" in parser.links


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
            tool_name="git_clone",
            artifact_type="source_code",
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


def test_normalize_web_interact_emits_sensitive_config_exposure_finding():
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "web_interactions.json").write_text(
            json.dumps(
                {
                    "pages": [
                        {
                            "url": "http://127.0.0.1:3001/rest/admin/application-configuration",
                            "title": "Application configuration",
                            "status_code": 200,
                            "surface": "api",
                            "session_label": "unauthenticated",
                            "auth_state": "none",
                            "requires_auth": False,
                            "content_length": 256,
                            "content_type": "application/json",
                            "response_preview": (
                                '{"config":{"server":{"baseUrl":"http://localhost:3000"},'
                                '"application":{"showVersionNumber":true,"localBackupEnabled":true}}}'
                            ),
                            "tool_source": "web_interact",
                            "vulnerability_type": "sensitive_data_exposure",
                            "severity": "high",
                            "confidence": 86,
                            "description": "Public application configuration data was returned.",
                            "request": (
                                "GET http://127.0.0.1:3001/rest/admin/application-configuration"
                            ),
                            "response": (
                                "HTTP/1.1 200\nContent-Type: application/json\n\n"
                                '{"config":{"server":{"baseUrl":"http://localhost:3000"}}}'
                            ),
                            "payload": "public_config_probe",
                            "exploit_result": "Configuration endpoint exposed internal settings.",
                            "verification_state": "detected",
                            "verification_confidence": 86,
                            "references": ["marker:config", "marker:baseurl"],
                        }
                    ],
                    "forms": [],
                    "sessions": [],
                    "workflows": [],
                    "replays": [],
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
        )

        assert artifact["findings"]
        finding = artifact["findings"][0]
        assert finding["endpoint"] == "http://127.0.0.1:3001/rest/admin/application-configuration"
        assert finding["target"] == "127.0.0.1"
        assert finding["vulnerability_type"] == "sensitive_data_exposure"
        assert finding["tool_source"] == "web_interact"
        assert finding["evidence"]["classification"]["verification_state"] == "detected"


def test_normalize_custom_poc_preserves_explicit_verified_state():
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "custom_poc.json").write_text(
            json.dumps(
                [
                    {
                        "title": "Authorization bypass confirmed via stateful replay",
                        "severity": "high",
                        "confidence": 82,
                        "target": "http://127.0.0.1:8088/login",
                        "endpoint": "http://127.0.0.1:8088/login",
                        "description": "Replay reached a privileged workflow state.",
                        "tool_source": "custom_poc",
                        "vulnerability_type": "auth_bypass",
                        "request": "GET /login",
                        "response": "HTTP/1.1 200 OK",
                        "payload": "cross_session",
                        "exploit_result": "privileged content returned",
                        "surface": "web",
                        "route_group": "/login",
                        "verification_state": "verified",
                        "verification_confidence": 93,
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
        )

        classification = artifact["findings"][0]["evidence"]["classification"]
        metadata = artifact["findings"][0]["evidence"]["metadata"]
        assert classification["verification_state"] == "verified"
        assert classification["verification_confidence"] == 93
        assert classification["verified"] is True
        assert metadata["verified_at"]


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


def test_normalize_graphql_cop_preserves_curl_verify_target_and_scope():
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "graphql_cop.json").write_text(
            json.dumps(
                [
                    {
                        "result": True,
                        "title": "Introspection",
                        "description": "Introspection Query Enabled",
                        "impact": "Information Leakage - /graphql",
                        "severity": "HIGH",
                        "curl_verify": (
                            "curl -X POST -H \"Content-Type: application/json\" "
                            "-d '{\"query\": \"query cop { __schema { types { name } } }\"}' "
                            "'http://127.0.0.1:8088/graphql'"
                        ),
                    }
                ]
            )
        )

        artifact = normalize_output(
            output_dir=tmpdir,
            output_parser="json",
            tool_name="graphql_cop",
            artifact_type="vulnerabilities",
            scan_id="scan-1",
            node_id="node-1",
            tenant_id="tenant-1",
            exit_code=0,
            scan_config={
                "scope": {
                    "allowed_hosts": ["127.0.0.1"],
                    "max_endpoints": 10,
                }
            },
        )

        assert artifact["item_count"] == 1
        assert artifact["metadata"]["guardrail_stats"]["filtered_out_of_scope"] == 0
        item = artifact["items"][0]
        assert item["endpoint"] == "http://127.0.0.1:8088/graphql"
        assert item["target"] == "127.0.0.1"
        assert "http://127.0.0.1:8088/graphql" in str(item["request"])
        finding = artifact["findings"][0]
        assert finding["vulnerability_type"] == "graphql_introspection"
        assert finding["endpoint"] == "http://127.0.0.1:8088/graphql"


def test_normalize_graphql_cop_preserves_multiple_surface_findings() -> None:
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "graphql_cop.json").write_text(
            json.dumps(
                [
                    {
                        "title": "Introspection",
                        "description": "Introspection Query Enabled",
                        "impact": "Information Leakage - /graphql",
                        "severity": "HIGH",
                        "curl_verify": "curl 'http://127.0.0.1:8088/graphql'",
                    },
                    {
                        "title": "Mutation is allowed over GET (possible CSRF)",
                        "description": "GraphQL mutations allowed using the GET method",
                        "impact": "Possible Cross Site Request Forgery - /graphql",
                        "severity": "MEDIUM",
                        "curl_verify": "curl 'http://127.0.0.1:8088/graphql?query=mutation+cop+%7B__typename%7D'",
                    },
                    {
                        "title": "Alias Overloading",
                        "description": "Alias Overloading with 100+ aliases is allowed",
                        "impact": "Denial of Service - /graphql",
                        "severity": "HIGH",
                        "curl_verify": "curl 'http://127.0.0.1:8088/graphql'",
                    },
                ]
            )
        )

        artifact = normalize_output(
            output_dir=tmpdir,
            output_parser="json",
            tool_name="graphql_cop",
            artifact_type="vulnerabilities",
            scan_id="scan-1",
            node_id="node-1",
            tenant_id="tenant-1",
            exit_code=0,
            scan_config={"scope": {"allowed_hosts": ["127.0.0.1"]}},
        )

        assert artifact["item_count"] == 3
        vulnerability_types = {item["vulnerability_type"] for item in artifact["items"]}
        assert "graphql_introspection" in vulnerability_types
        assert "csrf" in vulnerability_types
        assert "graphql_dos" in vulnerability_types


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


def test_worker_service_skips_terminal_scan_jobs(monkeypatch):
    import asyncio

    import app.services.worker_service as worker_service_module
    from app.services.worker_service import WorkerService

    class _FakeRedis:
        pass

    service = WorkerService(redis=_FakeRedis())
    cancelled_calls: list[dict[str, str | None]] = []

    async def _fake_load_scan_status(*, scan_id, tenant_id):
        del scan_id, tenant_id
        return "cancelled"

    async def _fake_mark_job_cancelled(**kwargs):
        cancelled_calls.append(
            {
                "job_id": str(kwargs["job_id"]),
                "reason": str(kwargs["reason"]),
            }
        )

    async def _noop(**kwargs):
        del kwargs
        return None

    def _unexpected_get_tool(*args, **kwargs):
        raise AssertionError("cancelled scan jobs must not resolve tools")

    monkeypatch.setattr(service, "_load_scan_status", _fake_load_scan_status)
    monkeypatch.setattr(service, "_mark_job_cancelled", _fake_mark_job_cancelled)
    monkeypatch.setattr(service, "_mark_job_claimed", _noop)
    monkeypatch.setattr(service, "_persist_job_claimed", _noop)
    monkeypatch.setattr(worker_service_module, "get_tool", _unexpected_get_tool)

    asyncio.run(
        service.execute_job(
            {
                "job_id": str(uuid.uuid4()),
                "scan_id": str(uuid.uuid4()),
                "tenant_id": str(uuid.uuid4()),
                "node_id": str(uuid.uuid4()),
                "dag_id": str(uuid.uuid4()),
                "tool": "httpx_probe",
                "target": "http://127.0.0.1:3001",
                "worker_family": "web",
                "config": {},
            }
        )
    )

    assert len(cancelled_calls) == 1
    assert "scan is cancelled" in cancelled_calls[0]["reason"].lower()


def test_worker_service_emits_failed_output_summary_with_execution_log(monkeypatch):
    import asyncio
    from types import SimpleNamespace

    import app.services.worker_service as worker_service_module
    from app.engine.container_runner import ContainerResult
    from app.services.worker_service import WorkerService

    class _FakeRedis:
        pass

    class _FakeEmitter:
        def __init__(self) -> None:
            self.failed_calls: list[dict[str, object]] = []

        async def emit_job_failed(self, **kwargs):
            self.failed_calls.append(kwargs)
            return "msg-1"

    service = WorkerService(redis=_FakeRedis())
    service._emitter = _FakeEmitter()  # type: ignore[assignment]

    async def _fake_load_scan_status(*, scan_id, tenant_id):
        del scan_id, tenant_id
        return "queued"

    async def _noop(**kwargs):
        del kwargs
        return None

    def _fake_get_tool(_tool_name):
        return SimpleNamespace(
            image="example/tool:latest",
            working_dir="/work",
            entrypoint=None,
            env_vars={},
            default_timeout=30,
            artifact_type="http_observation",
            output_parser="json",
        )

    def _fake_render_command(*args, **kwargs):
        del args, kwargs
        return ["fake-tool", "--target", "https://example.com"]

    async def _fake_run(**kwargs):
        del kwargs
        return ContainerResult(
            exit_code=2,
            stdout="line 1\nline 2",
            stderr="fatal: request failed",
            output_dir="/tmp/pentra/fake-output",
            timed_out=False,
            execution_mode="controlled_live_external",
            execution_provenance="live",
            execution_reason=None,
        )

    async def _unexpected_success():
        raise AssertionError("failed jobs must not mark success")

    async def _fake_cleanup_job(_job_id):
        return None

    monkeypatch.setattr(service, "_load_scan_status", _fake_load_scan_status)
    monkeypatch.setattr(service, "_mark_job_claimed", _noop)
    monkeypatch.setattr(service, "_persist_job_claimed", _noop)
    monkeypatch.setattr(service, "_persist_job_started", _noop)
    monkeypatch.setattr(service, "_mark_job_started", _noop)
    monkeypatch.setattr(service, "_mark_job_failed", _noop)
    monkeypatch.setattr(service, "_mark_job_succeeded", _unexpected_success)
    monkeypatch.setattr(service._runner, "run", _fake_run)
    monkeypatch.setattr(service._runner, "cleanup_job", _fake_cleanup_job)
    monkeypatch.setattr(worker_service_module, "get_tool", _fake_get_tool)
    monkeypatch.setattr(worker_service_module, "render_command", _fake_render_command)

    payload = {
        "job_id": str(uuid.uuid4()),
        "scan_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "node_id": str(uuid.uuid4()),
        "dag_id": str(uuid.uuid4()),
        "tool": "nuclei",
        "target": "https://example.com",
        "worker_family": "web",
        "config": {},
    }

    asyncio.run(service.execute_job(payload))

    assert len(service._emitter.failed_calls) == 1  # type: ignore[attr-defined]
    failed_call = service._emitter.failed_calls[0]  # type: ignore[attr-defined]
    assert failed_call["error_code"] == "EXIT_2"
    output_summary = failed_call["output_summary"]
    assert isinstance(output_summary, dict)
    assert output_summary["artifact_type"] == "http_observation"
    assert output_summary["summary"]["status"] == "failed"
    assert output_summary["execution_log"]["command"] == ["fake-tool", "--target", "https://example.com"]
    assert output_summary["execution_log"]["stdout_preview"].endswith("line 1\nline 2")
    assert output_summary["execution_log"]["stderr_preview"].endswith("fatal: request failed")
    assert output_summary["execution_log"]["full_stdout_artifact_ref"]
    assert output_summary["execution_log"]["full_stderr_artifact_ref"]
    assert output_summary["execution_log"]["command_artifact_ref"]
    assert output_summary["execution_log"]["exit_code"] == 2


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
