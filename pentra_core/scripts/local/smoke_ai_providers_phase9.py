#!/usr/bin/env python3
"""Phase 9 smoke: capture AI provider diagnostics from the local API."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import urlopen


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="Base URL for the local Pentra API",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Run live provider probes instead of config-only diagnostics",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    query = urlencode({"live": "true" if args.live else "false"})
    url = f"{args.base_url.rstrip('/')}/api/v1/scans/ai/providers/diagnostics?{query}"

    try:
        with urlopen(url, timeout=120) as response:
            payload = json.load(response)
    except HTTPError as exc:
        raise SystemExit(f"diagnostics request failed with HTTP {exc.code}: {exc.reason}") from exc
    except URLError as exc:
        raise SystemExit(f"diagnostics request failed: {exc.reason}") from exc

    artifact = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source_url": url,
        "payload": payload,
    }

    artifact_dir = Path(".local/pentra/phase9")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    latest_path = artifact_dir / "ai_provider_diagnostics_latest.json"
    latest_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")

    print(json.dumps(payload, indent=2))
    print(f"\nSaved diagnostics artifact to {latest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
