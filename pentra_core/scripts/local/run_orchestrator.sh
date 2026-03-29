#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VENV_DIR="${PENTRA_VENV_DIR:-$ROOT_DIR/.venv-phase0}"
SERVICE_DIR="$ROOT_DIR/pentra_core/services/orchestrator-svc"
PORT="${PENTRA_ORCHESTRATOR_PORT:-8001}"

if [ ! -x "$VENV_DIR/bin/python" ]; then
  echo "Backend virtualenv not found at $VENV_DIR. Run bootstrap_backend_env.sh first." >&2
  exit 1
fi

SHARED_ENV_FILE="${PENTRA_SHARED_ENV_FILE:-$ROOT_DIR/pentra_core/services/api-gateway/.env}"
if [ -f "$SHARED_ENV_FILE" ]; then
  set -a
  # Reuse the local AI/provider config without importing unrelated API-only
  # settings that may not parse correctly in the orchestrator process.
  # shellcheck disable=SC1091
  source <(
    grep -E '^(AI_REASONING_[A-Z0-9_]+=|AI_PROVIDER_PRIORITY=|ANTHROPIC_[A-Z0-9_]+=|OPENAI_[A-Z0-9_]+=|GROQ_[A-Z0-9_]+=|GEMINI_[A-Z0-9_]+=|OLLAMA_[A-Z0-9_]+=|AI_PROVIDER=|AI_API_KEY=|AI_MODEL=|OPENAI_API_BASE=|OPENAI_BASE_URL=)' "$SHARED_ENV_FILE" || true
  )
  set +a
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
export DATABASE_URL="${DATABASE_URL:-postgresql+asyncpg://pentra:pentra@localhost:5433/pentra_dev}"
export REDIS_URL="${REDIS_URL:-redis://localhost:6379/0}"
export PENTRA_DISABLE_AUTONOMY="${PENTRA_DISABLE_AUTONOMY:-true}"

cd "$SERVICE_DIR"
exec "$VENV_DIR/bin/python" -m uvicorn app.main:app --reload --host 0.0.0.0 --port "$PORT"
