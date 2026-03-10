"""MOD-04.5 Pipeline Engine tests — validates the full DAG execution lifecycle.

Tests:
  1. Node state machine transitions (pending→ready→running→completed/failed/skipped/blocked)
  2. ToolSpec & dependency validation
  3. Pipeline executor SQL correctness (source inspection)
  4. Failure propagation logic
  5. Phase completion evaluation with skipped nodes
  6. Progress calculation with resolved nodes (completed + skipped)

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_dag_pipeline.py -v
"""

from __future__ import annotations

import os
import sys
import uuid

_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


# ═══════════════════════════════════════════════════════════════════
# 1. Node state machine
# ═══════════════════════════════════════════════════════════════════


def test_node_transitions_map():
    """Validate the node state machine transition map."""
    from app.engine.state_manager import _NODE_TRANSITIONS

    # All expected states exist
    assert "pending" in _NODE_TRANSITIONS
    assert "ready" in _NODE_TRANSITIONS
    assert "scheduled" in _NODE_TRANSITIONS
    assert "running" in _NODE_TRANSITIONS
    assert "blocked" in _NODE_TRANSITIONS
    assert "failed" in _NODE_TRANSITIONS

    # Forward transitions
    assert "ready" in _NODE_TRANSITIONS["pending"]
    assert "skipped" in _NODE_TRANSITIONS["pending"]
    assert "running" in _NODE_TRANSITIONS["ready"]
    assert "scheduled" in _NODE_TRANSITIONS["ready"]
    assert "running" in _NODE_TRANSITIONS["scheduled"]
    assert "completed" in _NODE_TRANSITIONS["running"]
    assert "failed" in _NODE_TRANSITIONS["running"]
    assert "blocked" in _NODE_TRANSITIONS["running"]
    assert "ready" in _NODE_TRANSITIONS["blocked"]

    # Retry path
    assert "pending" in _NODE_TRANSITIONS["failed"]


def test_node_transitions_no_invalid():
    """Completed and skipped are terminal — no outgoing transitions."""
    from app.engine.state_manager import _NODE_TRANSITIONS

    assert "completed" not in _NODE_TRANSITIONS
    assert "skipped" not in _NODE_TRANSITIONS


def test_scan_transitions_include_completed():
    """Running scans should be able to transition to completed."""
    from app.engine.state_manager import _SCAN_TRANSITIONS

    assert "completed" in _SCAN_TRANSITIONS["running"]


# ═══════════════════════════════════════════════════════════════════
# 2. State manager methods exist with correct signatures
# ═══════════════════════════════════════════════════════════════════


def test_state_manager_has_ready_method():
    """State manager must have mark_node_ready."""
    from app.engine.state_manager import StateManager
    assert hasattr(StateManager, "mark_node_ready")


def test_state_manager_has_skipped_method():
    """State manager must have mark_node_skipped."""
    from app.engine.state_manager import StateManager
    assert hasattr(StateManager, "mark_node_skipped")


def test_state_manager_has_blocked_method():
    """State manager must have mark_node_blocked."""
    from app.engine.state_manager import StateManager
    assert hasattr(StateManager, "mark_node_blocked")


def test_state_manager_has_unblock_method():
    """State manager must have unblock_node."""
    from app.engine.state_manager import StateManager
    assert hasattr(StateManager, "unblock_node")


def test_state_manager_has_propagate_failure():
    """State manager must have propagate_failure."""
    from app.engine.state_manager import StateManager
    assert hasattr(StateManager, "propagate_failure")


def test_state_manager_has_transition_guard():
    """State manager must have _transition_node for guarded transitions."""
    from app.engine.state_manager import StateManager
    assert hasattr(StateManager, "_transition_node")


# ═══════════════════════════════════════════════════════════════════
# 3. Dependency Resolver — two-step resolution
# ═══════════════════════════════════════════════════════════════════


def test_resolver_has_resolve_ready_nodes():
    """DependencyResolver must have resolve_ready_nodes (pending → ready)."""
    from app.engine.dependency_resolver import DependencyResolver
    assert hasattr(DependencyResolver, "resolve_ready_nodes")


def test_resolver_has_get_ready_nodes():
    """DependencyResolver must have get_ready_nodes (selects ready state)."""
    from app.engine.dependency_resolver import DependencyResolver
    assert hasattr(DependencyResolver, "get_ready_nodes")


def test_resolver_get_ready_selects_ready_state():
    """get_ready_nodes SQL must select status = 'ready', not 'pending'."""
    import inspect
    from app.engine.dependency_resolver import DependencyResolver

    source = inspect.getsource(DependencyResolver.get_ready_nodes)
    assert "n.status = 'ready'" in source
    assert "n.status = 'pending'" not in source


def test_resolver_resolve_transitions_to_ready():
    """resolve_ready_nodes must UPDATE nodes to 'ready' state."""
    import inspect
    from app.engine.dependency_resolver import DependencyResolver

    source = inspect.getsource(DependencyResolver.resolve_ready_nodes)
    assert "SET status = 'ready'" in source
    assert "status = 'pending'" in source  # WHERE clause


# ═══════════════════════════════════════════════════════════════════
# 4. Job Dispatcher — dispatches from ready state
# ═══════════════════════════════════════════════════════════════════


def test_dispatcher_schedules_from_ready():
    """Job dispatcher must SET status = 'scheduled' WHERE status = 'ready'."""
    import inspect
    from app.engine.job_dispatcher import JobDispatcher

    source = inspect.getsource(JobDispatcher.dispatch_nodes)
    assert "status = 'ready'" in source
    assert "status = 'scheduled'" in source


# ═══════════════════════════════════════════════════════════════════
# 5. Pipeline Executor — coordinator
# ═══════════════════════════════════════════════════════════════════


def test_pipeline_executor_exists():
    """PipelineExecutor must be importable."""
    from app.engine.pipeline_executor import PipelineExecutor
    assert PipelineExecutor is not None


def test_pipeline_executor_has_start():
    from app.engine.pipeline_executor import PipelineExecutor
    assert hasattr(PipelineExecutor, "start_pipeline")


def test_pipeline_executor_has_after_completion():
    from app.engine.pipeline_executor import PipelineExecutor
    assert hasattr(PipelineExecutor, "execute_after_completion")


def test_pipeline_executor_has_after_failure():
    from app.engine.pipeline_executor import PipelineExecutor
    assert hasattr(PipelineExecutor, "execute_after_failure")


def test_pipeline_executor_composes_all_engines():
    """PipelineExecutor.__init__ must accept session and redis."""
    import inspect
    from app.engine.pipeline_executor import PipelineExecutor

    sig = inspect.signature(PipelineExecutor.__init__)
    params = list(sig.parameters.keys())
    assert "session" in params
    assert "redis" in params


def test_pipeline_executor_uses_all_components():
    """PipelineExecutor must use StateManager, DependencyResolver, PhaseController, JobDispatcher."""
    import inspect
    from app.engine.pipeline_executor import PipelineExecutor

    source = inspect.getsource(PipelineExecutor)
    assert "StateManager" in source
    assert "DependencyResolver" in source
    assert "PhaseController" in source
    assert "JobDispatcher" in source


# ═══════════════════════════════════════════════════════════════════
# 6. Phase Controller — uses resolve_ready_nodes
# ═══════════════════════════════════════════════════════════════════


def test_phase_controller_uses_resolve():
    """PhaseController must call resolve_ready_nodes, not get_ready_nodes."""
    import inspect
    from app.engine.phase_controller import PhaseController

    source = inspect.getsource(PhaseController)
    assert "resolve_ready_nodes" in source


def test_phase_completion_includes_skipped():
    """check_phase_complete must count skipped nodes."""
    import inspect
    from app.engine.dependency_resolver import DependencyResolver

    source = inspect.getsource(DependencyResolver.check_phase_complete)
    assert "'skipped'" in source


# ═══════════════════════════════════════════════════════════════════
# 7. Progress calculation — completed + skipped = resolved
# ═══════════════════════════════════════════════════════════════════


def test_progress_counts_skipped_as_resolved():
    """update_scan_progress must count both completed and skipped as done."""
    import inspect
    from app.engine.state_manager import StateManager

    source = inspect.getsource(StateManager.update_scan_progress)
    assert "'completed'" in source
    assert "'skipped'" in source
    assert "resolved" in source


# ═══════════════════════════════════════════════════════════════════
# 8. Orchestrator service delegates to PipelineExecutor
# ═══════════════════════════════════════════════════════════════════


def test_orchestrator_imports_pipeline_executor():
    """OrchestratorService must import PipelineExecutor."""
    import inspect
    from app.services.orchestrator_service import OrchestratorService

    source = inspect.getsource(sys.modules[OrchestratorService.__module__])
    assert "PipelineExecutor" in source


def test_orchestrator_uses_start_pipeline():
    """handle_scan_created must call start_pipeline."""
    import inspect
    from app.services.orchestrator_service import OrchestratorService

    source = inspect.getsource(OrchestratorService.handle_scan_created)
    assert "start_pipeline" in source


def test_orchestrator_uses_execute_after_completion():
    """handle_job_completed must call execute_after_completion."""
    import inspect
    from app.services.orchestrator_service import OrchestratorService

    source = inspect.getsource(OrchestratorService.handle_job_completed)
    assert "execute_after_completion" in source


def test_orchestrator_uses_execute_after_failure():
    """handle_job_failed must call execute_after_failure."""
    import inspect
    from app.services.orchestrator_service import OrchestratorService

    source = inspect.getsource(OrchestratorService.handle_job_failed)
    assert "execute_after_failure" in source


def test_orchestrator_calls_propagate_on_failure():
    """Pipeline executor's execute_after_failure must propagate failures."""
    import inspect
    from app.engine.pipeline_executor import PipelineExecutor

    source = inspect.getsource(PipelineExecutor.execute_after_failure)
    assert "propagate_failure" in source


# ═══════════════════════════════════════════════════════════════════
# 9. RetryManager — existing behavior preserved
# ═══════════════════════════════════════════════════════════════════


def test_retry_non_retryable():
    from app.engine.retry_manager import RetryManager
    mgr = RetryManager()
    assert mgr.should_retry(retry_count=0, max_retries=5, error_code="SCOPE_VIOLATION") is False


def test_retry_exhausted():
    from app.engine.retry_manager import RetryManager
    mgr = RetryManager()
    assert mgr.should_retry(retry_count=3, max_retries=3, error_code="TIMEOUT") is False


def test_retry_should_retry():
    from app.engine.retry_manager import RetryManager
    mgr = RetryManager()
    assert mgr.should_retry(retry_count=0, max_retries=2, error_code="TIMEOUT") is True


def test_backoff_exponential():
    from app.engine.retry_manager import RetryManager
    mgr = RetryManager()
    assert mgr.get_backoff_seconds(0) == 5.0
    assert mgr.get_backoff_seconds(1) == 10.0
    assert mgr.get_backoff_seconds(2) == 20.0
    assert mgr.get_backoff_seconds(10) == 120.0  # capped


# ═══════════════════════════════════════════════════════════════════
# 10. DAG templates — preserved from MOD-04
# ═══════════════════════════════════════════════════════════════════


def test_template_integrity():
    """All scan types must have valid phase/tool templates."""
    from app.engine.dag_builder import _PHASES, _TOOLS

    for scan_type in ["recon", "vuln", "full", "exploit_verify"]:
        assert scan_type in _PHASES, f"Missing phases for {scan_type}"
        assert scan_type in _TOOLS, f"Missing tools for {scan_type}"
        assert len(_PHASES[scan_type]) >= 2
        assert len(_TOOLS[scan_type]) >= 2


def test_dependency_edges_valid():
    """All depends_on refs must point to existing tools in the same template."""
    from app.engine.dag_builder import _TOOLS

    for scan_type, tools in _TOOLS.items():
        tool_names = {t.name for t in tools}
        for tool in tools:
            for dep in tool.depends_on:
                assert dep in tool_names, (
                    f"{tool.name} depends on {dep} which doesn't exist in {scan_type}"
                )


def test_toolspec_metadata():
    """Every ToolSpec must carry max_retries and timeout_seconds."""
    from app.engine.dag_builder import _TOOLS

    for tools in _TOOLS.values():
        for tool in tools:
            assert isinstance(tool.max_retries, int)
            assert isinstance(tool.timeout_seconds, int)
            assert tool.timeout_seconds > 0


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
