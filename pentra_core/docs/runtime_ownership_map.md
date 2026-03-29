# Runtime Ownership Map

Generated: 2026-03-27T15:26:09.856835+00:00

## Canonical Runtime Path

Only these paths are considered product runtime truth:

- `frontend`: Operator UI, runtime diagnostics, planner visibility, and scan launch.
- `services/api-gateway`: Canonical public API, websocket bridge, auth, and reporting surface.
- `services/orchestrator-svc`: Planner, capability advisory execution, DAG control, and runtime coordination.
- `services/worker-svc`: Live tool execution, capability-pack runtime, crawling, and verification.
- `packages/pentra-common`: Shared schemas, config, storage, auth, profiles, and provider routing.
- `knowledge`: Pinned methodology, corpus, ontology, target profiles, and capability graphs.
- `scripts/local`: Supported local boot and validation entrypoints for the canonical stack.
- `run_pentra_local.sh`: Top-level local stack launcher for the canonical stack.

## Quarantined Trees

These paths remain in-repo for reference only and must not be imported by canonical runtime code:

- `services/orchestrator-svc/app/engine/_experimental`: Quarantined shadow engine tree. Not supported for production/runtime imports.

## Canonical Entrypoints

- `run_pentra_local.sh`: Boots the canonical local product stack.
- `pentra_core/scripts/local/run_api.sh`: Starts api-gateway.
- `pentra_core/scripts/local/run_orchestrator.sh`: Starts orchestrator-svc.
- `pentra_core/scripts/local/run_worker.sh`: Starts worker-svc.

## Enforcement Notes

- Canonical runtime code must not import `app.engine._experimental`.
- Local startup scripts must only boot the canonical services listed above.
- Benchmark validation is separate from authorized field-validation operation.
