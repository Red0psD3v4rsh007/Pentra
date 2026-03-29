#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VENV_DIR="${PENTRA_VENV_DIR:-$ROOT_DIR/.venv-phase0}"
SERVICE_DIR="$ROOT_DIR/pentra_core/services/worker-svc"

if [ ! -x "$VENV_DIR/bin/python" ]; then
  echo "Backend virtualenv not found at $VENV_DIR. Run bootstrap_backend_env.sh first." >&2
  exit 1
fi

if [ -f "$SERVICE_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$SERVICE_DIR/.env"
  set +a
fi

export APP_ENV="${APP_ENV:-development}"
case "${DEBUG:-}" in
  true|false|1|0|yes|no|on|off)
    ;;
  *)
    export DEBUG=true
    ;;
esac

worker_health_port_default() {
  case "$1" in
    recon) echo "9101" ;;
    network) echo "9102" ;;
    web) echo "9103" ;;
    vuln) echo "9104" ;;
    exploit) echo "9105" ;;
    *) echo "9199" ;;
  esac
}

export PYTHONPATH="$ROOT_DIR/pentra_core/packages/pentra-common:$SERVICE_DIR${PYTHONPATH:+:$PYTHONPATH}"
export DATABASE_URL="${DATABASE_URL:-postgresql+asyncpg://pentra:pentra@localhost:5433/pentra_dev}"
export REDIS_URL="${REDIS_URL:-redis://localhost:6379/0}"
export WORKER_FAMILY="${1:-${WORKER_FAMILY:-recon}}"
export WORKER_FAMILY
export WORKER_EXECUTION_MODE="${WORKER_EXECUTION_MODE:-controlled_live_local}"
export WORKER_LIVE_TOOLS="${WORKER_LIVE_TOOLS:-scope_check,amass,nmap_discovery,httpx_probe,ffuf,nuclei,sqlmap,sqlmap_verify,custom_poc,web_interact}"
export WORKER_LIVE_TARGET_POLICY="${WORKER_LIVE_TARGET_POLICY:-local_only}"
export WORKER_HEALTH_HOST="${WORKER_HEALTH_HOST:-127.0.0.1}"
export WORKER_HEALTH_PORT="${WORKER_HEALTH_PORT:-$(worker_health_port_default "$WORKER_FAMILY")}"
export WORKER_PREWARM_IMAGES="${WORKER_PREWARM_IMAGES:-true}"
export WORKER_BLOCK_MS="${WORKER_BLOCK_MS:-1000}"
export WORKER_RECLAIM_IDLE_MS="${WORKER_RECLAIM_IDLE_MS:-5000}"
export WORKER_RECLAIM_HEARTBEAT_MS="${WORKER_RECLAIM_HEARTBEAT_MS:-1500}"

cd "$SERVICE_DIR"
exec "$VENV_DIR/bin/python" app/main.py
