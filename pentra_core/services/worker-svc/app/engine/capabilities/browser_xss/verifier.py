"""Safe canary-based browser verification helpers for the Browser XSS pack."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from typing import Any
import uuid
from urllib.parse import urlparse

from .payloads import instantiate_browser_xss_canary_plan


_PROBE_SUBPROCESS_ENV = "PENTRA_BROWSER_XSS_PROBE_SUBPROCESS"
_PROBE_PYTHON_ENV = "PENTRA_BROWSER_XSS_PROBE_PYTHON"
_WORKER_APP_ROOT = Path(__file__).resolve().parents[4]
_PENTRA_COMMON_ROOT = Path(__file__).resolve().parents[6] / "packages" / "pentra-common"
_PROBE_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "browser_xss_probe.py"

def build_canary_marker() -> str:
    return f"PENTRA_CANARY_{uuid.uuid4().hex[:12]}"


def summarize_canary_observations(
    *,
    request_url: str,
    verification_context: dict[str, object],
    canary_marker: str,
    observations: dict[str, Any],
) -> list[dict[str, object]]:
    sink_hits = observations.get("sink_hits") or []
    dom_mutations = observations.get("dom_mutations") or []
    if not isinstance(sink_hits, list):
        sink_hits = []
    if not isinstance(dom_mutations, list):
        dom_mutations = []

    observed_sinks = [
        str(item.get("sink") or "").strip()
        for item in sink_hits
        if isinstance(item, dict) and str(item.get("sink") or "").strip()
    ]
    if not observed_sinks and not dom_mutations:
        return []

    route_group = str(verification_context.get("route_group") or _browser_route_group(request_url)).strip() or "/"
    proof_contract = str(verification_context.get("proof_contract") or "browser_execution_xss").strip()
    attack_primitive = str(verification_context.get("attack_primitive") or "dom_xss_browser_probe").strip()
    planner_action = str(verification_context.get("planner_action") or "map_client_side_sinks").strip()
    flow_mode = str(verification_context.get("flow_mode") or "reflected").strip().lower()
    payload_archetype_key = str(verification_context.get("payload_archetype_key") or "").strip()
    severity = "high" if any(sink in {"eval", "Function", "setTimeout-string", "setInterval-string"} for sink in observed_sinks) else "medium"
    confidence = 95 if severity == "high" else 89
    title_prefix = "Stored browser canary reached dangerous DOM sink" if flow_mode == "stored" else "Browser canary reached dangerous DOM sink"
    description = (
        "Benign canary flow verification observed attacker-controlled input reaching a dangerous browser sink "
        f"on {route_group}. No executable exploit payloads were used."
    )
    observation_preview = {
        "observed_sinks": observed_sinks[:6],
        "dom_mutation_count": len(dom_mutations),
        "page_url": observations.get("page_url"),
    }
    return [
        {
            "target": request_url,
            "endpoint": request_url,
            "access_level": "browser_canary_flow",
            "title": title_prefix,
            "severity": severity,
            "confidence": confidence,
            "description": description,
            "request": f"GET {request_url}",
            "response": json.dumps(observation_preview, indent=2),
            "payload": f"canary:{canary_marker}",
            "exploit_result": (
                "Browser instrumentation observed benign canary propagation into a dangerous DOM sink."
            ),
            "surface": "web",
            "route_group": route_group,
            "vulnerability_type": "xss",
            "challenge_family": "xss",
            "attack_primitive": attack_primitive,
            "workflow_state": str(verification_context.get("workflow_state") or ""),
            "workflow_stage": str(verification_context.get("workflow_stage") or ""),
            "planner_action": planner_action,
            "proof_contract": proof_contract,
            "target_profile": str(verification_context.get("target_profile") or ""),
            "capability_pack": "p3a_browser_xss",
            "verification_state": "verified",
            "verification_confidence": confidence,
            "exploitability": "high" if severity == "high" else "medium",
            "exploitability_score": 90 if severity == "high" else 82,
            "references": [f"observed_sink:{sink}" for sink in observed_sinks[:6]]
            + [f"proof_contract:{proof_contract}", f"planner_action:{planner_action}"]
            + ([f"payload_archetype:{payload_archetype_key}"] if payload_archetype_key else [])
            + [f"source:{value}" for value in verification_context.get("source_markers", [])[:4]]
            + [f"sink:{value}" for value in verification_context.get("sink_markers", [])[:4]],
            "verification_context": {
                **verification_context,
                "canary_marker": canary_marker,
                "observed_sinks": observed_sinks[:6],
                "dom_mutation_count": len(dom_mutations),
            },
        }
    ]


async def verify_browser_xss_canary(payload: dict[str, object]) -> list[dict[str, object]]:
    request_url = str(payload.get("request_url") or "").strip()
    if not request_url:
        return []
    verification_context = payload.get("verification_context") or {}
    if not isinstance(verification_context, dict):
        verification_context = {}

    if not _playwright_import_available():
        if os.getenv(_PROBE_SUBPROCESS_ENV) == "1":
            raise RuntimeError("playwright is required for browser-backed XSS verification")
        return await _verify_browser_xss_canary_subprocess(payload)

    return await _verify_browser_xss_canary_native(
        payload=payload,
        request_url=request_url,
        verification_context=verification_context,
    )


def _playwright_import_available() -> bool:
    return importlib.util.find_spec("playwright") is not None


async def _verify_browser_xss_canary_subprocess(payload: dict[str, object]) -> list[dict[str, object]]:
    python_executable = str(os.getenv(_PROBE_PYTHON_ENV) or "python3").strip() or "python3"
    env = dict(os.environ)
    env[_PROBE_SUBPROCESS_ENV] = "1"

    python_path_entries = [str(_WORKER_APP_ROOT), str(_PENTRA_COMMON_ROOT)]
    current_pythonpath = env.get("PYTHONPATH")
    if current_pythonpath:
        python_path_entries.append(current_pythonpath)
    env["PYTHONPATH"] = os.pathsep.join(python_path_entries)

    with tempfile.TemporaryDirectory(prefix="pentra-browser-xss-") as temp_dir:
        input_path = Path(temp_dir) / "browser_xss_probe_input.json"
        output_path = Path(temp_dir) / "browser_xss_probe_output.json"
        input_path.write_text(json.dumps(payload))

        process = await asyncio.create_subprocess_exec(
            python_executable,
            str(_PROBE_SCRIPT_PATH),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            cwd=str(_WORKER_APP_ROOT),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            stderr_text = stderr.decode("utf-8", errors="replace").strip()
            stdout_text = stdout.decode("utf-8", errors="replace").strip()
            error_message = stderr_text or stdout_text or "unknown error"
            raise RuntimeError(
                f"playwright probe subprocess failed with exit code {process.returncode}: {error_message}"
            )
        if not output_path.exists():
            return []
        findings = json.loads(output_path.read_text() or "[]")
        if not isinstance(findings, list):
            return []
        return [item for item in findings if isinstance(item, dict)]


async def _verify_browser_xss_canary_native(
    *,
    payload: dict[str, object],
    request_url: str,
    verification_context: dict[str, Any],
) -> list[dict[str, object]]:
    from playwright.async_api import async_playwright

    flow_mode = str(verification_context.get("flow_mode") or "reflected").strip().lower()
    payload_plan = verification_context.get("payload_plan") or {}
    if not isinstance(payload_plan, dict):
        payload_plan = {}
    parameter_name = str(payload_plan.get("parameter_name") or verification_context.get("parameter_name") or "").strip() or None
    executable_path = str(payload.get("chromium_path") or os.getenv("PENTRA_CHROMIUM_PATH") or "/usr/bin/chromium")
    canary_marker = build_canary_marker()
    instantiated_plan = instantiate_browser_xss_canary_plan(
        payload_plan={
            **payload_plan,
            "request_url": payload_plan.get("request_url") or request_url,
            "parameter_name": payload_plan.get("parameter_name") or parameter_name,
        },
        canary_marker=canary_marker,
    )

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            executable_path=executable_path,
            args=["--disable-dev-shm-usage", "--no-sandbox"],
        )
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        await page.add_init_script(_instrumentation_script(canary_marker))

        try:
            if instantiated_plan.get("mode") == "stored_form" or flow_mode == "stored":
                form_action_url = str(instantiated_plan.get("submit_url") or verification_context.get("form_action_url") or request_url).strip()
                form_method = str(instantiated_plan.get("submit_method") or verification_context.get("form_method") or "POST").strip().upper()
                form_payload = instantiated_plan.get("form_payload") or {}
                if not isinstance(form_payload, dict):
                    form_payload = {}
                if form_method == "GET":
                    submit_url = str(
                        instantiated_plan.get("navigate_url")
                        or verification_context.get("submit_url")
                        or ""
                    ).strip()
                    if not submit_url:
                        submit_url = form_action_url
                    await page.goto(submit_url, wait_until="domcontentloaded", timeout=15000)
                else:
                    await context.request.post(form_action_url, form={str(key): str(value) for key, value in form_payload.items()})
                render_url = str(instantiated_plan.get("render_url") or verification_context.get("render_url") or request_url).strip() or request_url
                await page.goto(render_url, wait_until="domcontentloaded", timeout=15000)
            else:
                probe_url = str(instantiated_plan.get("navigate_url") or request_url).strip() or request_url
                await page.goto(probe_url, wait_until="domcontentloaded", timeout=15000)

            await page.wait_for_timeout(1500)
            observations = await page.evaluate(
                "() => window.__pentraBrowserCanaryState ? JSON.parse(JSON.stringify(window.__pentraBrowserCanaryState)) : {}"
            )
        finally:
            await context.close()
            await browser.close()

    if not isinstance(observations, dict):
        observations = {}
    return summarize_canary_observations(
        request_url=request_url,
        verification_context=verification_context,
        canary_marker=canary_marker,
        observations=observations,
    )


def _instrumentation_script(marker: str) -> str:
    marker_js = json.dumps(marker)
    return f"""
(() => {{
  const marker = {marker_js};
  const state = {{
    sink_hits: [],
    dom_mutations: [],
    page_url: location.href,
  }};
  const textOf = (value) => {{
    if (typeof value === 'string') return value;
    if (value == null) return '';
    try {{ return String(value); }} catch (_error) {{ return ''; }}
  }};
  const containsMarker = (value) => textOf(value).includes(marker);
  const record = (sink, value) => {{
    if (!containsMarker(value)) return;
    state.sink_hits.push({{
      sink,
      preview: textOf(value).slice(0, 240),
      page_url: location.href,
    }});
  }};
  window.__pentraBrowserCanaryState = state;

  const patchSetter = (proto, prop, sink) => {{
    try {{
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || typeof desc.set !== 'function') return;
      Object.defineProperty(proto, prop, {{
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set(value) {{
          record(sink, value);
          return desc.set.call(this, value);
        }},
      }});
    }} catch (_error) {{}}
  }};

  patchSetter(Element.prototype, 'innerHTML', 'innerHTML');
  patchSetter(Element.prototype, 'outerHTML', 'outerHTML');
  if (typeof HTMLIFrameElement !== 'undefined') {{
    patchSetter(HTMLIFrameElement.prototype, 'srcdoc', 'srcdoc');
  }}

  try {{
    const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(position, html) {{
      record('insertAdjacentHTML', html);
      return originalInsertAdjacentHTML.call(this, position, html);
    }};
  }} catch (_error) {{}}

  try {{
    const originalWrite = Document.prototype.write;
    Document.prototype.write = function(...args) {{
      for (const arg of args) record('document.write', arg);
      return originalWrite.apply(this, args);
    }};
  }} catch (_error) {{}}

  try {{
    const originalWriteln = Document.prototype.writeln;
    Document.prototype.writeln = function(...args) {{
      for (const arg of args) record('document.writeln', arg);
      return originalWriteln.apply(this, args);
    }};
  }} catch (_error) {{}}

  try {{
    const originalEval = window.eval;
    window.eval = function(value) {{
      record('eval', value);
      if (containsMarker(value)) return undefined;
      return originalEval.call(this, value);
    }};
  }} catch (_error) {{}}

  try {{
    const OriginalFunction = window.Function;
    window.Function = function(...args) {{
      const body = args.length ? args[args.length - 1] : '';
      record('Function', body);
      if (containsMarker(body)) {{
        return function pentraCanaryNoop() {{ return undefined; }};
      }}
      return OriginalFunction.apply(this, args);
    }};
    window.Function.prototype = OriginalFunction.prototype;
  }} catch (_error) {{}}

  try {{
    const originalSetTimeout = window.setTimeout;
    window.setTimeout = function(handler, timeout, ...args) {{
      if (typeof handler === 'string') {{
        record('setTimeout-string', handler);
        if (containsMarker(handler)) return 0;
      }}
      return originalSetTimeout.call(this, handler, timeout, ...args);
    }};
  }} catch (_error) {{}}

  try {{
    const originalSetInterval = window.setInterval;
    window.setInterval = function(handler, timeout, ...args) {{
      if (typeof handler === 'string') {{
        record('setInterval-string', handler);
        if (containsMarker(handler)) return 0;
      }}
      return originalSetInterval.call(this, handler, timeout, ...args);
    }};
  }} catch (_error) {{}}

  const scanNode = (node) => {{
    if (!node) return;
    const text = 'textContent' in node ? textOf(node.textContent) : '';
    if (containsMarker(text)) {{
      state.dom_mutations.push({{
        kind: 'textContent',
        preview: text.slice(0, 240),
        page_url: location.href,
      }});
    }}
    if (node.attributes) {{
      for (const attr of node.attributes) {{
        if (containsMarker(attr.value)) {{
          state.dom_mutations.push({{
            kind: `attribute:${{attr.name}}`,
            preview: textOf(attr.value).slice(0, 240),
            page_url: location.href,
          }});
        }}
      }}
    }}
  }};

  const observer = new MutationObserver((mutations) => {{
    for (const mutation of mutations) {{
      if (mutation.type === 'characterData') {{
        scanNode(mutation.target);
      }}
      for (const node of mutation.addedNodes || []) {{
        scanNode(node);
      }}
      if (mutation.type === 'attributes') {{
        scanNode(mutation.target);
      }}
    }}
  }});

  const startObserver = () => {{
    if (!document.documentElement) return;
    observer.observe(document.documentElement, {{
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
    }});
    scanNode(document.documentElement);
  }};

  if (document.readyState === 'loading') {{
    document.addEventListener('DOMContentLoaded', startObserver, {{ once: true }});
  }} else {{
    startObserver();
  }}
}})();
"""


def _browser_route_group(target_url: str) -> str:
    parsed = urlparse(target_url)
    if parsed.fragment.startswith("/"):
        fragment = parsed.fragment.split("?", 1)[0].strip("/")
        return f"/#/{fragment}" if fragment else "/#"
    path = (parsed.path or "/").strip("/")
    return f"/{path}" if path else "/"
