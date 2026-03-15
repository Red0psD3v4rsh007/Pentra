# Phase 6 Local Stateful Slice

This runbook verifies Pentra's first autonomous web-interaction slice:

- authenticated crawling
- cookie + CSRF handling
- form discovery and safe replay
- workflow-aware follow-up via `custom_poc`

## 1. Start the local stack

```bash
./pentra_core/scripts/local/bootstrap_backend_env.sh
docker compose -f docker-compose.local.yml up -d postgres redis
./pentra_core/scripts/local/migrate_and_seed.sh
```

## 2. Start the demo target

```bash
./pentra_core/scripts/local/run_phase3_demo_target.sh
```

The same local demo target now includes:

- `/login`
- `/portal/dashboard`
- `/portal/account`
- `/portal/orders/new`
- `/portal/checkout/cart`
- `/portal/checkout/confirm`

## 3. Start API + workers

```bash
env ALLOWED_ORIGINS='["http://localhost:3006","http://127.0.0.1:3006"]' ./pentra_core/scripts/local/run_api.sh
./pentra_core/scripts/local/run_worker.sh recon
./pentra_core/scripts/local/run_worker.sh network
./pentra_core/scripts/local/run_worker.sh web
./pentra_core/scripts/local/run_worker.sh vuln
./pentra_core/scripts/local/run_worker.sh exploit
```

## 4. Start the orchestrator with autonomy enabled

Phase 6 relies on exploration-generated workflow mutation nodes, so do not use the default autonomy-disabled local runner.

```bash
env PENTRA_DISABLE_AUTONOMY=false ./pentra_core/scripts/local/run_orchestrator.sh
```

## 5. Run the smoke test

```bash
.venv-phase0/bin/python pentra_core/scripts/local/smoke_phase6_stateful.py
```

Expected outcomes:

- `web_interact` completes
- authenticated session context is recorded
- forms are discovered and replayed safely
- `custom_poc` workflow-mutation jobs are dispatched
- at least one stateful finding surfaces through the API
