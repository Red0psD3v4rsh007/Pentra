#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
FRONTEND_DIR="$ROOT_DIR/pentra_core/frontend"
PORT="${PENTRA_FRONTEND_PORT:-3000}"

if ! command -v pnpm >/dev/null 2>&1; then
  echo "pnpm is required to run the frontend locally." >&2
  exit 1
fi

cd "$FRONTEND_DIR"

if [ ! -d node_modules ]; then
  pnpm install --frozen-lockfile
fi

exec pnpm dev --port "$PORT"
