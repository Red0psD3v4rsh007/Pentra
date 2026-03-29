"""Unit tests for the pipeline fixes — verifiable without live services.

Tests:
  1. RetryManager logic (no deps)
  2. DAGBuilder ToolSpec templates (validate phase/node/edge counts)
  3. JobDispatcher SQL includes all required NOT NULL columns
  4. ConcurrencyController idempotency logic

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_pipeline_fixes.py -v
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid

# Ensure project in path
_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


# ── Test 1: RetryManager ─────────────────────────────────────────────

def test_retry_manager_non_retryable_errors():
    """Non-retryable error codes should always return False."""
    from app.engine.retry_manager import RetryManager

    mgr = RetryManager()
    for code in ["SCOPE_VIOLATION", "AUTH_FAILURE", "INVALID_TARGET", "QUOTA_EXCEEDED", "LICENCE_EXPIRED"]:
        assert mgr.should_retry(retry_count=0, max_retries=5, error_code=code) is False


def test_retry_manager_max_retries_exhausted():
    """When retry_count >= max_retries, should not retry."""
    from app.engine.retry_manager import RetryManager

    mgr = RetryManager()
    assert mgr.should_retry(retry_count=3, max_retries=3, error_code="TIMEOUT") is False
    assert mgr.should_retry(retry_count=5, max_retries=3, error_code="TIMEOUT") is False


def test_retry_manager_should_retry():
    """When retryable and under limit, should retry."""
    from app.engine.retry_manager import RetryManager

    mgr = RetryManager()
    assert mgr.should_retry(retry_count=0, max_retries=2, error_code="TIMEOUT") is True
    assert mgr.should_retry(retry_count=1, max_retries=2, error_code="CONNECTION_ERROR") is True


def test_retry_manager_does_not_retry_dalfox_timeouts():
    """Dalfox timeouts are high-cost and should fail fast instead of recycling."""
    from app.engine.retry_manager import RetryManager

    mgr = RetryManager()
    assert (
        mgr.should_retry(
            retry_count=0,
            max_retries=2,
            error_code="TIMEOUT",
            tool_name="dalfox",
        )
        is False
    )


def test_retry_manager_does_not_retry_cors_scanner_exit_1():
    """Template/config failures in the CORS scanner should fail fast."""
    from app.engine.retry_manager import RetryManager

    mgr = RetryManager()
    assert (
        mgr.should_retry(
            retry_count=0,
            max_retries=2,
            error_code="EXIT_1",
            tool_name="cors_scanner",
        )
        is False
    )


def test_retry_manager_backoff():
    """Exponential backoff calculation."""
    from app.engine.retry_manager import RetryManager

    mgr = RetryManager()
    assert mgr.get_backoff_seconds(0) == 5.0    # 5 * 2^0
    assert mgr.get_backoff_seconds(1) == 10.0   # 5 * 2^1
    assert mgr.get_backoff_seconds(2) == 20.0   # 5 * 2^2
    assert mgr.get_backoff_seconds(3) == 40.0   # 5 * 2^3
    assert mgr.get_backoff_seconds(10) == 120.0  # capped at 120


# ── Test 2: DAG Templates ────────────────────────────────────────────

def test_recon_template():
    """Recon scan type should have 2 phases and 4 tools."""
    from app.engine.dag_builder import _PHASES, _TOOLS

    phases = _PHASES["recon"]
    tools = _TOOLS["recon"]

    assert len(phases) == 2, f"Expected 2 phases, got {len(phases)}"
    assert phases[0].number == 0 and phases[0].name == "scope_validation"
    assert phases[1].number == 1 and phases[1].name == "recon"

    assert len(tools) == 4, f"Expected 4 tools, got {len(tools)}"
    tool_names = {t.name for t in tools}
    assert "scope_check" in tool_names
    assert "subfinder" in tool_names
    assert "amass" in tool_names
    assert "nmap_discovery" in tool_names


def test_full_template():
    """Full scan type should have 7 phases and include all tools."""
    from app.engine.dag_builder import _PHASES, _TOOLS

    phases = _PHASES["full"]
    tools = _TOOLS["full"]

    assert len(phases) == 7, f"Expected 7 phases, got {len(phases)}"
    assert len(tools) >= 10, f"Expected 10+ tools, got {len(tools)}"

    # Verify phase chain
    phase_numbers = [p.number for p in phases]
    assert phase_numbers == [0, 1, 2, 3, 4, 5, 6]


def test_vuln_template():
    """Vuln scan type should have 4 phases."""
    from app.engine.dag_builder import _PHASES, _TOOLS

    phases = _PHASES["vuln"]
    tools = _TOOLS["vuln"]

    assert len(phases) == 4
    assert len(tools) >= 7


def test_external_web_api_full_profile_toolchain():
    """Profile-specific full scans should expose only the honest product-safe toolchain."""
    from pentra_common.profiles import prepare_scan_config
    from app.engine.dag_builder import _select_tools

    config = prepare_scan_config(
        scan_type="full",
        asset_type="web_app",
        asset_target="http://127.0.0.1:8088",
        config={"profile_id": "external_web_api_v1"},
    )
    tools = _select_tools(
        "full",
        "web_app",
        config,
    )
    tool_names = [tool.name for tool in tools]

    assert "scope_check" in tool_names
    assert "httpx_probe" in tool_names
    assert "web_interact" in tool_names
    assert "ffuf" in tool_names
    assert "nuclei" in tool_names
    assert "sqlmap" in tool_names
    assert "dalfox" in tool_names
    assert "graphql_cop" in tool_names
    assert "cors_scanner" in tool_names
    assert "ai_triage" in tool_names
    assert "report_gen" in tool_names
    assert tool_names.index("httpx_probe") < tool_names.index("nuclei")
    assert tool_names.index("scope_check") < tool_names.index("httpx_probe")
    assert "metasploit" not in tool_names
    assert "zap" not in tool_names
    assert "subfinder" not in tool_names
    assert "amass" not in tool_names
    assert "nmap_discovery" not in tool_names
    assert "nmap_svc" not in tool_names
    assert "jwt_tool" not in tool_names
    assert "header_audit_tool" not in tool_names


def test_safe_live_tools_include_sast_pipeline_tools():
    from pentra_common.profiles import _SAFE_LIVE_TOOLS

    for tool_name in [
        "git_clone",
        "semgrep",
        "trufflehog",
        "dependency_audit",
        "api_spec_parser",
    ]:
        assert tool_name in _SAFE_LIVE_TOOLS


def test_enforce_safe_scan_config_accepts_sast_allowed_live_tools():
    from pentra_common.profiles import enforce_safe_scan_config

    config = {
        "scope": {
            "target": "http://127.0.0.1:8088",
            "allowed_hosts": ["127.0.0.1"],
            "allowed_domains": [],
            "allowed_cidrs": [],
            "max_subdomains": 5,
            "max_endpoints": 10,
            "max_depth": 1,
        },
        "execution": {
            "mode": "controlled_live_local",
            "target_policy": "local_only",
            "allowed_live_tools": [
                "scope_check",
                "git_clone",
                "semgrep",
                "trufflehog",
                "dependency_audit",
                "api_spec_parser",
            ],
        },
        "rate_limits": {
            "http_requests_per_minute": 30,
            "ffuf_requests_per_minute": 10,
            "nuclei_requests_per_minute": 10,
            "sqlmap_threads": 1,
            "zap_minutes": 1,
        },
        "verification_policy": {
            "max_dynamic_nodes_per_scan": 1,
            "max_verifications_per_type": 1,
        },
        "stateful_testing": {
            "max_pages": 1,
            "max_replays": 1,
        },
    }

    normalized = enforce_safe_scan_config(
        scan_type="full",
        asset_type="web_app",
        asset_target="http://127.0.0.1:8088",
        config=config,
    )

    assert normalized["execution"]["allowed_live_tools"] == [
        "scope_check",
        "git_clone",
        "semgrep",
        "trufflehog",
        "dependency_audit",
        "api_spec_parser",
    ]


def test_orchestrator_retries_scan_lock_for_job_events():
    from app.services.orchestrator_service import OrchestratorService

    class FakeConcurrency:
        def __init__(self) -> None:
            self.calls = 0

        async def acquire_scan_lock(self, scan_id, holder="orchestrator") -> bool:
            self.calls += 1
            return self.calls >= 3

    service = OrchestratorService(session_factory=None, redis=None)  # type: ignore[arg-type]
    service._concurrency = FakeConcurrency()

    acquired = asyncio.run(
        service._acquire_scan_lock_with_retry(
            uuid.uuid4(),
            attempts=5,
            delay_seconds=0.0,
        )
    )

    assert acquired is True
    assert service._concurrency.calls == 3


def test_unknown_scan_type():
    """Unknown scan type should NOT be in templates."""
    from app.engine.dag_builder import _PHASES, _TOOLS

    assert "nonexistent" not in _PHASES
    assert "nonexistent" not in _TOOLS


# ── Test 3: ToolSpec metadata propagation ────────────────────────────

def test_toolspec_carries_retry_timeout():
    """Every ToolSpec should have max_retries and timeout_seconds."""
    from app.engine.dag_builder import _TOOLS

    for scan_type, tools in _TOOLS.items():
        for tool in tools:
            assert hasattr(tool, "max_retries"), f"{tool.name} missing max_retries"
            assert hasattr(tool, "timeout_seconds"), f"{tool.name} missing timeout_seconds"
            assert isinstance(tool.max_retries, int)
            assert isinstance(tool.timeout_seconds, int)
            assert tool.timeout_seconds > 0


def test_node_config_json_serialization():
    """The config JSON should contain max_retries and timeout_seconds."""
    from app.engine.dag_builder import _TOOLS

    for tool in _TOOLS["recon"]:
        config = json.dumps({
            "max_retries": tool.max_retries,
            "timeout_seconds": tool.timeout_seconds,
        })
        parsed = json.loads(config)
        assert "max_retries" in parsed
        assert "timeout_seconds" in parsed
        assert parsed["max_retries"] == tool.max_retries


# ── Test 4: DependencyResolver ReadyNode contract ────────────────────

def test_ready_node_dataclass():
    """ReadyNode should have all required fields."""
    from app.engine.dependency_resolver import ReadyNode

    node = ReadyNode(
        node_id=uuid.uuid4(),
        dag_id=uuid.uuid4(),
        phase_id=uuid.uuid4(),
        tool="nmap",
        worker_family="network",
        config={"max_retries": 2, "timeout_seconds": 600},
        input_refs={},
    )
    assert node.tool == "nmap"
    assert node.config["max_retries"] == 2
    assert node.config["timeout_seconds"] == 600


# ── Test 5: Verify fixed SQL strings ────────────────────────────────

def test_job_dispatcher_sql_has_required_columns():
    """Verify that the INSERT SQL in job_dispatcher includes all NOT NULL columns."""
    import inspect
    from app.engine.job_dispatcher import JobDispatcher

    source = inspect.getsource(JobDispatcher.dispatch_nodes)

    # These columns are NOT NULL without server_default in the scan_jobs schema
    assert "priority" in source, "INSERT must include 'priority' column"
    assert "retry_count" in source, "INSERT must preserve 'retry_count' across retries"
    assert "max_retries" in source, "INSERT must include 'max_retries' column"
    assert "timeout_seconds" in source, "INSERT must include 'timeout_seconds' column"

    # This column does NOT exist on scan_nodes — must not be referenced
    # We had a bug where started_at was used in UPDATE scan_nodes
    assert "started_at" not in source, "scan_nodes has no started_at column"


def test_pipeline_executor_forwards_scan_config_to_dispatcher():
    """The dispatcher should receive scan config for profile-aware workers."""
    import inspect
    from app.engine.pipeline_executor import PipelineExecutor

    source = inspect.getsource(PipelineExecutor)
    assert "_load_scan_config" in source
    assert "config=scan_config" in source


def test_job_dispatcher_merges_scan_and_node_config():
    from app.engine.job_dispatcher import _merge_configs

    merged = _merge_configs(
        {
            "execution": {"target_policy": "local_only"},
            "rate_limits": {"sqlmap_threads": 1},
        },
        {
            "verification_context": {"request_url": "http://127.0.0.1:8088/api/v1/auth/login"},
            "execution": {"allowed_live_tools": ["sqlmap_verify"]},
        },
    )

    assert merged["execution"]["target_policy"] == "local_only"
    assert merged["execution"]["allowed_live_tools"] == ["sqlmap_verify"]
    assert merged["verification_context"]["request_url"].endswith("/api/v1/auth/login")


def test_dag_builder_applies_selected_check_tool_exclusions():
    from app.engine.dag_builder import ToolSpec, _apply_tool_exclusions

    tools = [
        ToolSpec("httpx_probe", "web", phase=1),
        ToolSpec("dalfox", "web", phase=3),
        ToolSpec("cors_scanner", "web", phase=3),
    ]

    filtered = _apply_tool_exclusions(
        tools,
        {"selected_checks": {"exclude_tools": ["dalfox", "cors_scanner"]}},
    )

    assert [tool.name for tool in filtered] == ["httpx_probe"]


def test_external_web_profile_honors_selected_check_tool_exclusions():
    from pentra_common.profiles import prepare_scan_config
    from app.engine.dag_builder import _select_tools

    config = prepare_scan_config(
        scan_type="full",
        asset_type="web_app",
        asset_target="http://127.0.0.1:3001",
        config={
            "profile_id": "external_web_api_v1",
            "selected_checks": {
                "exclude_tools": ["dalfox", "cors_scanner"],
                "http_probe_paths": ["/", "/rest/products/search?q=test"],
                "content_paths": ["rest/products/search?q=test"],
            },
        },
    )

    tools = _select_tools("full", "web_app", config)
    tool_names = [tool.name for tool in tools]

    assert "dalfox" not in tool_names
    assert "cors_scanner" not in tool_names
    assert "nuclei" in tool_names
    assert "sqlmap" in tool_names


def test_dag_builder_node_config_includes_toolspec():
    """Verify DAGBuilder serializes ToolSpec data into node config."""
    import inspect
    from app.engine.dag_builder import DAGBuilder

    source = inspect.getsource(DAGBuilder.build_dag)
    assert "max_retries" in source
    assert "timeout_seconds" in source
    assert "json.dumps" in source


def test_dag_builder_edge_inserts_are_idempotent():
    """Dependency edges should tolerate duplicate logical keys without crashing the DAG build."""
    import inspect
    from app.engine.dag_builder import DAGBuilder

    source = inspect.getsource(DAGBuilder.build_dag)
    assert "ON CONFLICT (source_node_id, target_node_id, data_key) DO NOTHING" in source


# ── Test 6: Dependency edge wiring ───────────────────────────────────

def test_tool_dependencies_valid():
    """All depends_on references should point to tools that exist in the same template."""
    from app.engine.dag_builder import _TOOLS

    for scan_type, tools in _TOOLS.items():
        tool_names = {t.name for t in tools}
        for tool in tools:
            for dep in tool.depends_on:
                assert dep in tool_names, (
                    f"Tool '{tool.name}' in scan_type '{scan_type}' "
                    f"depends on '{dep}' which doesn't exist in the template"
                )


# ── Test 7: Phase min_success_ratio values ────────────────────────────

def test_phase_success_ratios():
    """Verify min_success_ratio values match architecture spec."""
    from app.engine.dag_builder import _PHASES

    full_phases = {p.name: p.min_success_ratio for p in _PHASES["full"]}
    assert full_phases["scope_validation"] == 1.0
    assert full_phases["recon"] == 0.33
    assert full_phases["enum"] == 0.50
    assert full_phases["vuln_scan"] == 0.66
    assert full_phases["exploit_verify"] == 1.0


# ── Run directly ─────────────────────────────────────────────────────

if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
