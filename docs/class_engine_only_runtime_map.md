# Class Engine Only Runtime Map
## A1. Entrypoints and call graph
### Artifact builder
- SQL entrypoint: `build_base(...)` in `artifact_builder/artifact_builder.c:1182`.
- Builder flow:
  - policy parse: `parse_policy_file(...)` at `artifact_builder/artifact_builder.c:1195`
  - strict atom/domain checks: `artifact_builder/artifact_builder.c:1264`
  - code artifacts + CSR bins emit: `artifact_builder/artifact_builder.c:2171`
  - bin manifest emit: `artifact_builder/artifact_builder.c:2193`

### Executor interception
- init/hook registration: `_PG_init(...)` in `custom_filter/custom_filter.c:707`.
- planner/executor hooks:
  - `cf_planner_hook(...)` at `custom_filter/custom_filter.c:976`
  - `cf_rel_pathlist_hook(...)` at `custom_filter/custom_filter.c:1001`
  - `cf_executor_start(...)` at `custom_filter/custom_filter.c:1764`
  - custom scan begin/exec: `cf_begin(...)` at `custom_filter/custom_filter.c:4268`, `cf_exec(...)` at `custom_filter/custom_filter.c:4350`
- policy runtime callsite: `policy_run(...)` invoked at `custom_filter/custom_filter.c:2607`.

### Policy runtime
- entrypoint: `policy_run(...)` at `custom_filter/policy.cpp:8527`.
- target evaluation:
  - `build_target_allow_list(...)` at `custom_filter/policy.cpp:8190`
  - `eval_formula_root_words(...)` at `custom_filter/policy.cpp:7971`
  - `eval_term_conjunction_words(...)` at `custom_filter/policy.cpp:7679`
- strict dispatch routes in term evaluator:
  - `eval_term_conjunction_pf2_single_hub(...)` at `custom_filter/policy.cpp:4614`
  - `eval_term_conjunction_pf2_two_hop(...)` at `custom_filter/policy.cpp:5007`
  - `eval_term_conjunction_pf2_cycle_rect(...)` at `custom_filter/policy.cpp:6823`
  - `eval_term_conjunction_pf2_tree(...)` at `custom_filter/policy.cpp:6954`
  - unsupported shape fail-loud at `custom_filter/policy.cpp:7962` to `custom_filter/policy.cpp:7968`.

## A2. Algorithmic modes present now
### Mode 1: Class engine (active)
- start: `eval_term_conjunction_words(...)` at `custom_filter/policy.cpp:7679`.
- behavior: SAT selector model -> conjunction term -> class-route solve -> stamp `block_words`.
- strict reachability: YES.
- theory alignment: YES.

### Mode 2: SAT Boolean control plane (active)
- CNF/Tseitin build: `build_formula_cnf_tseitin(...)` at `custom_filter/policy.cpp:781`.
- selector enumeration loop: `eval_formula_root_words(...)` at `custom_filter/policy.cpp:8039`.
- strict reachability: YES.
- theory alignment: YES (Boolean control only).

### Mode 3: Enforcement mode switch (active)
- filter vs CTID/tidscan enforcement in executor path: `custom_filter/custom_filter.c:3075`.
- strict reachability: YES.
- theory alignment: YES.

## A3. Reachability proof
### Class route proof
- dispatch callsites:
  - single-hub path at `custom_filter/policy.cpp:7874`
  - two-hop path at `custom_filter/policy.cpp:7896`
  - cycle-rect path at `custom_filter/policy.cpp:7918`
  - tree path at `custom_filter/policy.cpp:7940`
- runtime proof:
  - per-term route marker emitted via `class_route_term` notice at `custom_filter/policy.cpp:7301`.
  - strict profile counters emitted in `policy_profile_query` at `custom_filter/policy.cpp:7311` and include `class_terms_ok/class_terms_reject/class_route_*`.
  - strict perf evidence: `logs/pf_v2_6_perf.csv` and `logs/pf_v2_7_perf.csv` show class counters + `proj_sig_count=0`, `proj_mask_or_ops=0`, `proj_rid_iters=0`.

### Competing-path absence proof
- PFV3 removed from runtime:
  - `rg -n "\bpfv3\b|PFV3" custom_filter/custom_filter.c custom_filter/policy.cpp custom_filter/policy_evaluator.cpp` -> no matches.
- query-driven runtime removed:
  - `rg -n "query_driven" custom_filter/custom_filter.c custom_filter/policy.cpp custom_filter/policy_evaluator.cpp` -> no matches.
- ActiveSig legacy entrypoints removed:
  - `rg -n "propagate_clause|refine_witness_active_sigs|project_active_signatures_to_block_words|ActiveSig" custom_filter/custom_filter.c custom_filter/policy.cpp` -> no matches.
- legacy operator scaffolding removed:
  - `rg -n "POLICY_OP_IN|POLICY_OP_LIKE|ConstOp::IN|ConstOp::LIKE|like_match" custom_filter/policy.cpp custom_filter/policy_evaluator.cpp` -> no matches.

## Strict-mode behavior summary
- enforced:
  - strict unsupported term shape -> ERROR in `custom_filter/policy.cpp:7962` to `custom_filter/policy.cpp:7968`.
  - runtime parser/evaluator supports only `{=, !=, <, <=, >, >=}` (legacy `IN`/`LIKE` paths removed).
- strict runtime route: class-engine only.
