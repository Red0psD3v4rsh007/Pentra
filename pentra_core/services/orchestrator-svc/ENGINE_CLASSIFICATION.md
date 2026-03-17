# Engine Classification — Orchestrator Service

Every module in `app/engine/` is classified into one of four tiers.
This manifest is the source of truth; each file also carries a
`__classification__` string at module level for grep-ability.

## Tiers

| Tier | Meaning |
|---|---|
| `runtime_hot_path` | Directly imported by `orchestrator_service.py` — load-bearing |
| `runtime_optional` | Transitively reachable — used during scans but not load-bearing |
| `experimental` | Never imported at runtime — parked in `_experimental/` |
| `test_support_only` | Only used by test fixtures (currently none) |

---

## `runtime_hot_path` (9 files)

| Module | Role |
|---|---|
| `artifact_bus` | Routes tool outputs to downstream engines (attack graph, exploit planning) |
| `concurrency_controller` | Limits parallel job dispatch per scan |
| `dag_builder` | Builds the initial tool DAG from scan profile |
| `dependency_resolver` | Resolves inter-job dependencies and determines ready nodes |
| `job_dispatcher` | Publishes ready jobs to Redis Streams for workers |
| `phase_controller` | Manages phase transitions (recon → web → vuln → exploit) |
| `pipeline_executor` | Main execution loop — drives the scan from start to completion |
| `retry_manager` | Handles job retries with backoff |
| `state_manager` | Persistent scan/job state tracking in PostgreSQL |

## `runtime_optional` (27 files)

| Module | Role |
|---|---|
| `attack_graph_builder` | Constructs the attack graph from completed findings |
| `exploit_chain_generator` | Generates multi-step exploit chains |
| `exploit_planner` | Plans exploitation strategies based on findings |
| `exploit_policy` | Policy constraints for exploit execution |
| `exploration_budget` | Budget tracking for autonomous exploration |
| `exploration_engine` | Autonomous exploration with hypothesis testing |
| `exploration_memory` | Short-term memory for exploration sessions |
| `exploration_scorer` | Scores exploration hypotheses |
| `graph_correlator` | Cross-references attack graph nodes with findings |
| `heuristic_matcher` | Matches findings against known heuristic patterns |
| `heuristic_test_generator` | Generates targeted tests from heuristic matches |
| `hypothesis_generator` | Generates attack hypotheses from findings |
| `impact_verifier` | Verifies finding impact through targeted checks |
| `interaction_mapper` | Maps application interaction surfaces |
| `path_enumerator` | Enumerates attack paths through the graph |
| `path_scorer` | Scores attack paths by exploitability |
| `pattern_chain_generator` | Chains pattern matches into attack sequences |
| `pattern_executor` | Executes matched patterns |
| `pattern_graph_builder` | Builds pattern graphs for reasoning |
| `pattern_matcher` | Pattern matching against knowledge base |
| `pattern_reasoner` | Reasoning over pattern match results |
| `recon_asset_analyzer` | Analyzes reconnaissance results against asset graph |
| `recon_memory` | Memory for reconnaissance sessions |
| `recon_planner` | Plans reconnaissance activities |
| `state_graph_builder` | Builds application state graphs |
| `strategy_engine` | Selects offensive strategies |
| `workflow_mutator` | Mutates scan workflows based on findings |

## `experimental` (39 files — in `_experimental/`)

| Module | Reason it's parked |
|---|---|
| `action_selector` | Not wired into any runtime path |
| `anomaly_detector` | Not wired into any runtime path |
| `asset_graph_builder` | Superseded by attack_graph_builder |
| `attack_hypothesis_generator` | Separate from wired hypothesis_generator |
| `attack_narrative` | Report support only, not called at runtime |
| `attack_planner` | Superseded by exploit_planner |
| `behavior_analyzer` | Not wired into any runtime path |
| `budget_manager` | Superseded by exploration_budget |
| `chain_learning` | ML capability, not integrated |
| `complexity_controller` | Not wired into any runtime path |
| `compliance_mapper` | Report support only |
| `coverage_tracker` | Not wired into any runtime path |
| `cross_domain_correlator` | Not wired into any runtime path |
| `differential_analyzer` | Not wired into any runtime path |
| `discovery_behavior_analyzer` | Not wired into any runtime path |
| `evidence_extractor` | Report support only |
| `expansion_engine` | Not wired into any runtime path |
| `experiment_engine` | Not wired into any runtime path |
| `exploit_feedback_analyzer` | ML capability, not integrated |
| `exploit_learning` | ML capability, not integrated |
| `feedback_controller` | Not wired into any runtime path |
| `heuristic_analyzer` | Separate from wired heuristic_matcher |
| `hypothesis_deduplicator` | Not wired into any runtime path |
| `hypothesis_graph` | Not wired into any runtime path |
| `learning_store` | ML capability, not integrated |
| `payload_evaluator` | Not wired into any runtime path |
| `payload_learning` | ML capability, not integrated |
| `payload_mutator` | Not wired into any runtime path |
| `report_generator` | Report support only |
| `response_collector` | Not wired into any runtime path |
| `response_normalizer` | Not wired into any runtime path |
| `result_validator` | Not wired into any runtime path |
| `retry_planner` | Separate from wired retry_manager |
| `risk_prioritizer` | Report support only |
| `scenario_runner` | Not wired into any runtime path |
| `session_manager` | Not wired into any runtime path |
| `strategy_refiner` | Separate from wired strategy_engine |
| `surface_risk_scorer` | Not wired into any runtime path |
| `target_clusterer` | Not wired into any runtime path |

## Knowledge Directory

| File | Tier |
|---|---|
| `knowledge/heuristics.yaml` | `runtime_optional` |
| `knowledge/payloads.yaml` | `runtime_optional` |
| `knowledge/recon_actions.yaml` | `runtime_optional` |
| `knowledge/pattern_registry.py` | `runtime_optional` |
