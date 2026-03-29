#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VENV_DIR="${PENTRA_VENV_DIR:-$ROOT_DIR/.venv-phase0}"
PYTHON_BIN="$VENV_DIR/bin/python"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Backend virtualenv not found at $VENV_DIR. Run bootstrap_backend_env.sh first." >&2
  exit 1
fi

if ! "$PYTHON_BIN" -c "import pytest" >/dev/null 2>&1; then
  echo "pytest is not installed in $VENV_DIR. Re-run bootstrap_backend_env.sh." >&2
  exit 1
fi

run_suite() {
  local service_dir="$1"
  local label="$2"
  shift 2

  echo
  echo "[validate] $label"
  (
    cd "$service_dir"
    "$PYTHON_BIN" -m pytest "$@"
  )
}

echo "[validate] Running Pentra backend validation suites"
echo "[validate] Using interpreter: $PYTHON_BIN"

run_suite \
  "$ROOT_DIR/pentra_core/services/api-gateway" \
  "API Gateway" \
  tests/test_terminal_phase1.py \
  tests/test_ws_scans_phase1.py \
  tests/test_cancel_scan_phase1.py \
  tests/test_scan_create_commit_phase2.py \
  tests/test_runtime_correctness_phase3.py \
  tests/test_execution_truth_phase7.py \
  tests/test_ai_reasoning_session_boundaries_phase4.py \
  tests/test_ai_runtime_phase7.py \
  tests/test_ai_provider_router_phase9.py \
  tests/test_scan_idempotency_phase4.py \
  tests/test_pause_resume_scheduling_phase5.py \
  tests/test_multi_target_asset_groups_phase5.py \
  tests/test_reporting_integrations_phase5.py \
  tests/test_reporting_phase7.py \
  tests/test_release_evidence_phase7.py \
  tests/test_phase8_capability_matrix.py \
  tests/test_phase9_capability_matrix.py \
  tests/test_intelligence_service.py \
  tests/test_intelligence_phase5.py \
  tests/test_historical_findings_phase5.py \
  tests/test_benchmark_expansion_phase7.py \
  -q

run_suite \
  "$ROOT_DIR/pentra_core/services/orchestrator-svc" \
  "Orchestrator" \
  tests/test_scan_cancellation_phase1.py \
  tests/test_job_event_durability_phase2.py \
  tests/test_dispatch_outbox_phase2.py \
  tests/test_concurrency_unification_phase3.py \
  tests/test_node_state_guards_phase3.py \
  tests/test_phase_failure_semantics_phase3.py \
  tests/test_pause_resume_phase5.py \
  tests/test_ai_strategy_advisor_phase7.py \
  tests/test_ai_strategy_followup_phase9.py \
  tests/test_phase9_planner_effect.py \
  tests/test_strategy_artifact_storage_phase6.py \
  tests/test_recon_runtime_phase6.py \
  tests/test_event_reclaim_phase6.py \
  tests/test_historical_finding_archive_phase5.py \
  -q

run_suite \
  "$ROOT_DIR/pentra_core/services/orchestrator-svc" \
  "Orchestrator allowlist regressions" \
  tests/test_pipeline_fixes.py \
  -k "safe_live_tools_include_sast_pipeline_tools or enforce_safe_scan_config_accepts_sast_allowed_live_tools or external_web_api_full_profile_toolchain" \
  -q

run_suite \
  "$ROOT_DIR/pentra_core/services/worker-svc" \
  "Worker" \
  tests/test_job_consumer_reclaim_phase2.py \
  tests/test_artifact_storage_paths_phase4.py \
  tests/test_worker_observability_phase4.py \
  tests/test_job_timing_phase7.py \
  -q

run_suite \
  "$ROOT_DIR/pentra_core/services/worker-svc" \
  "Worker verification regressions" \
  tests/test_worker.py \
  -k "normalize_sqlmap_verify_output_marks_finding_verified or normalize_custom_poc_preserves_explicit_verified_state" \
  -q

echo
echo "[validate] Backend validation suites passed"
