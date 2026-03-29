"""Browser-backed safe canary verification helper for local controlled targets."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[5]
PENTRA_COMMON_ROOT = REPO_ROOT / "pentra_core" / "packages" / "pentra-common"
WORKER_SERVICE_ROOT = Path(__file__).resolve().parents[2]
if str(PENTRA_COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(PENTRA_COMMON_ROOT))
if str(WORKER_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKER_SERVICE_ROOT))

from app.engine.capabilities.browser_xss import verify_browser_xss_canary


async def _main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    payload = json.loads(Path(args.input).read_text())
    findings = await verify_browser_xss_canary(payload)
    Path(args.output).write_text(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(asyncio.run(_main()))
