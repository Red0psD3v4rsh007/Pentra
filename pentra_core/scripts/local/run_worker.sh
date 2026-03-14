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

export PYTHONPATH="$ROOT_DIR/pentra_core/packages/pentra-common:$SERVICE_DIR${PYTHONPATH:+:$PYTHONPATH}"
export REDIS_URL="${REDIS_URL:-redis://localhost:6379/0}"
export WORKER_FAMILY="${1:-${WORKER_FAMILY:-recon}}"
export WORKER_FAMILY
export WORKER_EXECUTION_MODE="${WORKER_EXECUTION_MODE:-simulate}"

cd "$SERVICE_DIR"
exec "$VENV_DIR/bin/python" app/main.py
