#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VENV_DIR="${PENTRA_VENV_DIR:-$ROOT_DIR/.venv-phase0}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python executable not found: $PYTHON_BIN" >&2
  exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel
"$VENV_DIR/bin/pip" install -e "$ROOT_DIR/pentra_core/packages/pentra-common"
"$VENV_DIR/bin/pip" install -r "$ROOT_DIR/pentra_core/requirements-local.txt"

echo
echo "Backend environment ready:"
echo "  VENV_DIR=$VENV_DIR"
echo "Activate it with:"
echo "  source \"$VENV_DIR/bin/activate\""
