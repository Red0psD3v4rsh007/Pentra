#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VENV_DIR="${PENTRA_VENV_DIR:-$ROOT_DIR/.venv-phase0}"
PORT="${PENTRA_PHASE3_DEMO_PORT:-8088}"

if [ ! -x "$VENV_DIR/bin/python" ]; then
  echo "Backend virtualenv not found at $VENV_DIR. Run bootstrap_backend_env.sh first." >&2
  exit 1
fi

export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

cd "$ROOT_DIR"
exec "$VENV_DIR/bin/python" -m uvicorn pentra_core.dev_targets.external_web_api_v1_demo.app:app --host 127.0.0.1 --port "$PORT"
