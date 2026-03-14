#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VENV_DIR="${PENTRA_VENV_DIR:-$ROOT_DIR/.venv-phase0}"
SERVICE_DIR="$ROOT_DIR/pentra_core/services/api-gateway"
PORT="${PENTRA_API_PORT:-8000}"

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
export PYTHONPATH="$ROOT_DIR/pentra_core/packages/pentra-common:$SERVICE_DIR${PYTHONPATH:+:$PYTHONPATH}"

cd "$SERVICE_DIR"
exec "$VENV_DIR/bin/python" -m uvicorn app.main:app --reload --host 0.0.0.0 --port "$PORT"
