#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VENV_DIR="${PENTRA_VENV_DIR:-$ROOT_DIR/.venv-phase0}"
API_ENV_FILE="$ROOT_DIR/pentra_core/services/api-gateway/.env"

if [ ! -x "$VENV_DIR/bin/python" ]; then
  echo "Backend virtualenv not found at $VENV_DIR. Run bootstrap_backend_env.sh first." >&2
  exit 1
fi

if [ -f "$API_ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$API_ENV_FILE"
  set +a
fi

export DATABASE_URL="${DATABASE_URL:-postgresql+asyncpg://pentra:pentra@localhost:5433/pentra_dev}"
export APP_ENV="${APP_ENV:-development}"
case "${DEBUG:-}" in
  true|false|1|0|yes|no|on|off)
    ;;
  *)
    export DEBUG=true
    ;;
esac
export PYTHONPATH="$ROOT_DIR/pentra_core/services/api-gateway:$ROOT_DIR/pentra_core/packages/pentra-common${PYTHONPATH:+:$PYTHONPATH}"

"$VENV_DIR/bin/alembic" -c "$ROOT_DIR/pentra_core/migrations/alembic.ini" upgrade head
"$VENV_DIR/bin/python" "$ROOT_DIR/pentra_core/scripts/seed_dev_data.py"
