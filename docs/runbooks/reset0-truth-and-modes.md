# Reset 0: Truth and Mode Separation

Date: March 15, 2026

This runbook defines the runtime truth contract for Pentra.

## Runtime Modes

- `demo_simulated`
  - explicit demo mode only
  - worker tools may use simulated outputs
  - UI and APIs must surface provenance as `simulated`
- `controlled_live_local`
  - live execution for local-only targets
  - unsupported tools must surface as `blocked`
  - blocked targets must surface as `blocked`
- `controlled_live_scoped`
  - live execution for in-scope targets
  - unsupported tools must surface as `blocked`
  - out-of-scope targets must surface as `blocked`

## Current Live Tool Matrix

Live now:

- `scope_check`
- `httpx_probe`
- `ffuf`
- `nuclei`
- `sqlmap`
- `sqlmap_verify`
- `custom_poc`
- `web_interact`

Not live yet in the main product path:

- `subfinder`
- `amass`
- `nmap_discovery`
- `nmap_svc`
- `zap`

## Product Truth Rules

- No silent simulation in `controlled_live_local` or `controlled_live_scoped`
- Every scan job must expose execution truth:
  - `live`
  - `simulated`
  - `blocked`
  - `inferred`
- Every persisted artifact summary must carry execution truth
- Findings must inherit execution truth from the artifact or evidence that produced them
- Reports must summarize execution truth so operators know what truly ran

## Current UI/API Contract

- Jobs:
  - blocked tools appear as `blocked` in scan detail
- Artifacts:
  - artifact summaries expose execution mode, provenance, and reason
- Findings:
  - finding detail exposes execution provenance and reason
- Reports:
  - report responses expose `execution_summary`
  - markdown export includes an `Execution Truth` section

## Notes

- Attack graphs, reports, and AI advisory are derived layers. They should be treated as `inferred`, not raw tool proof.
- If a future scan profile schedules a non-live tool, Pentra should show that honestly instead of pretending it ran.
