# Pentra Local Phase 3 Live Slice

This runbook validates Pentra's first real web/API scan profile using a strictly controlled local target.

What this run proves:

- Pentra can launch the `external_web_api_v1` profile against a real target
- `httpx_probe`, `ffuf`, `nuclei`, and `sqlmap` run live inside Docker
- scope and rate guardrails stay bounded to the seeded local target
- the scan produces normalized artifacts, persisted findings, evidence, attack graph data, and a report

What this run does not prove yet:

- live recon against arbitrary external customer domains
- authenticated crawling or browser-driven workflow testing
- safe exploit verification beyond the narrow current toolchain
- production deployment or multi-tenant hardening

## 1. Start local infrastructure and backend env

From the repo root:

```bash
docker compose -f docker-compose.local.yml up -d
./pentra_core/scripts/local/bootstrap_backend_env.sh
./pentra_core/scripts/local/migrate_and_seed.sh
```

The seed now includes the Phase 3 demo asset:

- asset `55555555-5555-5555-5555-555555555555`
- name `Phase 3 Demo API`
- target `http://127.0.0.1:8088`

## 2. Start the local demo target

In its own terminal:

```bash
./pentra_core/scripts/local/run_phase3_demo_target.sh
```

This boots a deliberately vulnerable local FastAPI app used only for Phase 3 verification.

Important:

- this target is intentionally insecure
- it is only for local Pentra validation
- do not expose it publicly

## 3. Start Pentra services

Terminal 1:

```bash
./pentra_core/scripts/local/run_api.sh
```

Terminal 2:

```bash
./pentra_core/scripts/local/run_orchestrator.sh
```

Terminal 3:

```bash
./pentra_core/scripts/local/run_worker.sh recon
```

Terminal 4:

```bash
./pentra_core/scripts/local/run_worker.sh network
```

Terminal 5:

```bash
./pentra_core/scripts/local/run_worker.sh web
```

Terminal 6:

```bash
./pentra_core/scripts/local/run_worker.sh vuln
```

Terminal 7:

```bash
./pentra_core/scripts/local/run_worker.sh exploit
```

Optional Terminal 8:

```bash
./pentra_core/scripts/local/run_frontend.sh
```

## 4. Guardrails active in this mode

`run_worker.sh` now defaults to a hybrid execution mode for the live slice:

- `WORKER_EXECUTION_MODE=hybrid`
- `WORKER_LIVE_TOOLS=httpx_probe,ffuf,nuclei,sqlmap`
- `WORKER_LIVE_TARGET_POLICY=local_only`

That means:

- only the allowlisted Phase 3 tools execute live
- they only execute against local targets such as `127.0.0.1` or `localhost`
- the rest of the pipeline remains deterministic and simulation-backed

The canonical profile is defined in:

- `pentra_core/packages/pentra-common/pentra_common/profiles.py`

## 5. Run the Phase 3 smoke test

With the services above running:

```bash
.venv-phase0/bin/python pentra_core/scripts/local/smoke_phase3_live.py
```

Expected success behavior:

- API and orchestrator health endpoints respond
- the demo target responds on `/healthz`
- a `full` scan is created for the seeded demo asset
- `httpx_probe`, `ffuf`, `nuclei`, and `sqlmap` complete
- the scan reaches `completed`
- Pentra returns real findings, evidence, attack graph data, and a report
- PostgreSQL shows `scan_artifacts` and `findings` rows for the scan

## 6. Useful local URLs

- API docs: `http://localhost:8000/docs`
- scans API: `http://localhost:8000/api/v1/scans`
- frontend: `http://localhost:3000`
- demo target: `http://127.0.0.1:8088`
- demo target OpenAPI: `http://127.0.0.1:8088/openapi.json`
- demo target GraphQL: `http://127.0.0.1:8088/graphql`

## 7. Common issues

### Live tools silently fall back to simulation

Check:

- Docker is running
- workers were restarted after the Phase 3 env changes
- `WORKER_EXECUTION_MODE` is not set back to `simulate`
- `WORKER_LIVE_TOOLS` still includes `httpx_probe,ffuf,nuclei,sqlmap`

### The demo target is up, but live tools cannot reach it

Check:

- the target is listening on `127.0.0.1:8088`
- workers are using Docker host networking for local live runs
- you are scanning the seeded local asset, not a remote target

### Scan creation is blocked by concurrent scan limits

If previous local scans were interrupted, reset stale local scan rows and tenant quota counts before re-running the smoke test.
