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
    """All 12 YAML tool specs must be loaded."""
    from app.tools.tool_registry import get_all_tools
    tools = get_all_tools()
    assert len(tools) >= 12, f"Expected >= 12 tools, got {len(tools)}"


def test_registry_has_expected_tools():
    """Every tool referenced in DAGBuilder must exist in the registry."""
    from app.tools.tool_registry import get_tool

    expected = [
        "scope_check", "subfinder", "amass", "nmap_discovery",
        "nmap_svc", "ffuf", "nuclei", "zap", "sqlmap",
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
