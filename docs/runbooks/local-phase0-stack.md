# Pentra Local Phase 0 Stack

This runbook turns Pentra into a locally runnable development stack for Phase 0.

What this stack proves:

- PostgreSQL and Redis are running locally
- the API gateway starts cleanly
- the orchestrator consumes `scan.created`
- workers process jobs in simulation mode
- a scan reaches a terminal state
- at least one artifact is stored in PostgreSQL

What this stack does not prove yet:

- real frontend-to-backend integration
- real Docker-based tool execution
- real LLM reasoning
- production infrastructure

## 1. Start local infrastructure

From the repo root:

```bash
docker compose -f docker-compose.local.yml up -d
```

This starts:

- PostgreSQL on `localhost:5433`
- Redis on `localhost:6379`

## 2. Prepare the backend Python environment

```bash
./pentra_core/scripts/local/bootstrap_backend_env.sh
```

This creates a local virtualenv at `.venv-phase0` by default and installs the backend dependencies required for:

- `pentra-common`
- API gateway
- orchestrator
- worker
- migrations
- smoke test tooling

## 3. Optional: copy local env files

The stack has sane defaults already, but you can copy the examples if you want explicit local overrides:

```bash
cp pentra_core/services/api-gateway/.env.example pentra_core/services/api-gateway/.env
cp pentra_core/services/orchestrator-svc/.env.example pentra_core/services/orchestrator-svc/.env
cp pentra_core/services/worker-svc/.env.example pentra_core/services/worker-svc/.env
cp pentra_core/frontend/.env.example pentra_core/frontend/.env.local
```

Important local default:

- `WORKER_EXECUTION_MODE=simulate`
- `PENTRA_DISABLE_AUTONOMY=true`

That keeps Phase 0 deterministic and avoids needing Docker tool images or autonomous expansion paths just to validate the core pipeline.

## 4. Run migrations and seed the dev tenant

```bash
./pentra_core/scripts/local/migrate_and_seed.sh
```

This applies Alembic migrations and seeds:

- tenant `22222222-2222-2222-2222-222222222222`
- user `11111111-1111-1111-1111-111111111111`
- project `33333333-3333-3333-3333-333333333333`
- asset `44444444-4444-4444-4444-444444444444`

The API already has a local dev-auth bypass that uses the seeded tenant and user.

## 5. Start services in separate terminals

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

Optional Terminal 5:

```bash
./pentra_core/scripts/local/run_frontend.sh
```

Frontend note:

- the UI will boot locally
- the main product UI is still mock-driven in Phase 0
- the smoke test below validates the backend pipeline, not frontend API integration
- the frontend runner installs dependencies automatically on first run if `node_modules` is missing

## 6. Run the smoke test

With the services above running:

```bash
.venv-phase0/bin/python pentra_core/scripts/local/smoke_phase0.py
```

Expected success behavior:

- API `/health` and `/ready` respond
- orchestrator `/health` responds
- a `recon` scan is created
- DAG and scan jobs are created
- recon/network workers complete jobs in simulation mode
- the scan reaches a terminal status
- at least one `scan_artifacts` row exists for the scan

## 7. Useful local URLs

- API docs: `http://localhost:8000/docs`
- API health: `http://localhost:8000/health`
- API readiness: `http://localhost:8000/ready`
- orchestrator health: `http://localhost:8001/health`
- frontend: `http://localhost:3000`

## 8. Common issues

### Migrations fail with `gen_random_uuid`

Phase 0 now enables the `pgcrypto` extension during the initial migration. If you are using an old local database volume, recreate it:

```bash
docker compose -f docker-compose.local.yml down -v
docker compose -f docker-compose.local.yml up -d
```

### Scan never leaves `queued` or `validating`

Check that these are all running:

- API
- orchestrator
- `recon` worker
- `network` worker
- Redis
- PostgreSQL

### Scan is created but no artifacts appear

Make sure the worker is in simulation mode or Docker is available:

- `WORKER_EXECUTION_MODE=simulate`

Artifacts are stored locally under `/tmp/pentra/artifacts` by default.
