# Capability Benchmarks

This folder defines the benchmark targets for Phase 8 and Phase 9.

The purpose is to measure Pentra by offensive capability, not by orchestration
health alone.

## Current State

- the repo currently ships one benchmarkable local target:
  [external_web_api_v1_demo](/home/kaal/Desktop/pentra/pentra_core/dev_targets/external_web_api_v1_demo)
- the Phase 8 harness uses that target as the first wired benchmark because its
  ground truth is repo-visible and already reflected in the Phase 6/7 proof
- the Phase 9 benchmark pack adds committed launch recipes and per-target
  manifests for harder local apps:
  - [juice_shop.json](/home/kaal/Desktop/pentra/pentra_core/dev_targets/capability_benchmarks/juice_shop.json)
  - [dvwa.json](/home/kaal/Desktop/pentra/pentra_core/dev_targets/capability_benchmarks/dvwa.json)
  - [webgoat.json](/home/kaal/Desktop/pentra/pentra_core/dev_targets/capability_benchmarks/webgoat.json)
  - [crapi.json](/home/kaal/Desktop/pentra/pentra_core/dev_targets/capability_benchmarks/crapi.json)
- the Phase 10 parser/upload scaffold adds a repo-local target manifest:
  - [repo_parser_upload_demo.json](/home/kaal/Desktop/pentra/pentra_core/dev_targets/capability_benchmarks/repo_parser_upload_demo.json)
  - local launcher: [run_phase10_parser_demo_target.sh](/home/kaal/Desktop/pentra/pentra_core/scripts/local/run_phase10_parser_demo_target.sh)
  - target app: [app.py](/home/kaal/Desktop/pentra/pentra_core/dev_targets/parser_upload_demo/app.py)

## Manifest

The Phase 8 baseline definition lives in
[phase8_target_matrix.json](/home/kaal/Desktop/pentra/pentra_core/dev_targets/capability_benchmarks/phase8_target_matrix.json).

The expanded Phase 9 benchmark pack lives in
[phase9_target_matrix.json](/home/kaal/Desktop/pentra/pentra_core/dev_targets/capability_benchmarks/phase9_target_matrix.json).

The constrained Phase 9 return pack lives in
[phase9_return_matrix.json](/home/kaal/Desktop/pentra/pentra_core/dev_targets/capability_benchmarks/phase9_return_matrix.json).

Each target should define:

- launch mode and target URL
- launch recipe when the target is not repo-native
- health check URL
- exact version pin and benchmark inventory for the running target when
  challenge content changes across releases
- scan plans to run
- expected vulnerability types
- expected verified vulnerability types
- minimum detected recall / verified recall / verified share

Targets can also declare:

- `expected_target_profile_keys`
- `pack_coverage_expectations`
- explicit benchmark-input policy per pack

For example, the pinned local Juice Shop manifest currently targets image
`bkimminich/juice-shop@sha256:9d65de715135ec9ba7667335d02cf9c1b70f6cbe2ff1d454d1d1d3c22744c336`,
whose container labels report app version `19.2.1`. Its live
`/api/Challenges` inventory on March 24, 2026 exposed `111` challenges across
`16` categories. That means the benchmark contract for this target must be
version-pinned to that inventory, not to some older or broader Juice Shop
challenge count found elsewhere online.

## Runners

Use the Phase 8 capability runner:

```bash
.venv-phase0/bin/python pentra_core/scripts/local/run_phase8_capability_matrix.py
```

It writes the latest artifact to:

```text
.local/pentra/phase8/capability_matrix_latest.json
```

Use the Phase 9 expanded benchmark runner:

```bash
.venv-phase0/bin/python pentra_core/scripts/local/run_phase9_capability_matrix.py
```

To run the constrained return pack first:

```bash
PENTRA_PHASE9_TARGET_MATRIX_PATH=pentra_core/dev_targets/capability_benchmarks/phase9_return_matrix.json \
.venv-phase0/bin/python pentra_core/scripts/local/run_phase9_capability_matrix.py
```

It writes the latest artifact to:

```text
.local/pentra/phase9/capability_matrix_latest.json
```

To preflight the harder benchmark targets directly, use:

```bash
./pentra_core/scripts/local/run_phase9_benchmark_targets.sh status
./pentra_core/scripts/local/run_phase9_benchmark_targets.sh ensure all
```

## Important Rule

Do not count a harder benchmark as useful just because the container boots.
If the launch recipe is not reproducible or the expected vulnerability subset
is not explicit, the benchmark is not useful.

## Phase 9 Return Rule

Phase 9 benchmark expansion resumes only in constrained form.

- restart on `2` to `3` controlled apps first, not the full pack at once
- score success on verified recall and verified share, not raw finding count
- treat authenticated and workflow-heavy targets as conditional proof lanes
  until stateful runtime depth materially improves
- only count tool families that emit canonical artifacts, replayable evidence,
  and planner-consumable summaries under strict product contracts
