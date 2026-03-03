# Deleted Engines Report
## Scope
This report tracks code removed to enforce class-engine-only strict runtime.

## 1) Removed competing engines
### PFV3
- Status: removed from runtime sources.
- Evidence:
  - `rg -n "\bpfv3\b|PFV3" custom_filter/policy.cpp custom_filter/custom_filter.c custom_filter/policy_evaluator.cpp` -> no matches.
- Result: no PFV3 gate/solver/planner/stub path remains.

### Query-driven runtime scaffolding
- Status: removed from runtime sources.
- Evidence:
  - `rg -n "query_driven" custom_filter/policy.cpp custom_filter/custom_filter.c custom_filter/policy_evaluator.cpp` -> no matches.
- Result: strict runtime has no query-driven branch.

### ActiveSig legacy entrypoints + helper blocks
- Status: removed.
- Evidence:
  - `rg -n "propagate_clause|refine_witness_active_sigs|project_active_signatures_to_block_words|ActiveSig" custom_filter/policy.cpp custom_filter/custom_filter.c` -> no matches.
- Removed code includes legacy entrypoints and dead helper clusters (signature/table support/pruning/pair-bundle remnants) from `custom_filter/policy.cpp`.

### Legacy operator scaffolding (`IN`/`LIKE`)
- Status: removed from runtime parser/evaluator path.
- Evidence:
  - `rg -n "POLICY_OP_IN|POLICY_OP_LIKE|ConstOp::IN|ConstOp::LIKE|like_match" custom_filter/policy.cpp custom_filter/policy_evaluator.cpp` -> no matches.
- Result: strict/runtime operator surface is physically limited to `{=, !=, <, <=, >, >=}`.

## 2) One true strict runtime path
- `policy_run(...)` -> `build_target_allow_list(...)` -> `eval_formula_root_words(...)` -> `eval_term_conjunction_words(...)`.
- Strict class routes only:
  - `single_hub`: `custom_filter/policy.cpp:7874`
  - `two_hop`: `custom_filter/policy.cpp:7896`
  - `cycle_rect`: `custom_filter/policy.cpp:7918`
  - `tree`: `custom_filter/policy.cpp:7940`
  - `reject/fail-loud`: `custom_filter/policy.cpp:7962` to `custom_filter/policy.cpp:7968`

## 3) Validation evidence (drona)
### Correctness
- `logs/stage9_correctness.csv` / `logs/stage9_correctness.md`: PASS (`8/8`) after latest sanitized runtime sync.
- `logs/pf_v2_6_correctness.csv` / `logs/pf_v2_6_correctness.md`: PASS.
- `logs/pf_v2_7_correctness.csv` / `logs/pf_v2_7_correctness.md`: PASS.

### Perf sanity + strict invariants
- `logs/pf_v2_6_perf.csv` / `logs/pf_v2_6_perf.md`.
- `logs/pf_v2_7_perf.csv` / `logs/pf_v2_7_perf.md`.
- Invariant audit in strict runs:
  - `proj_sig_count=0`
  - `proj_mask_or_ops=0`
  - `proj_rid_iters=0`

## 4) Current status
- Runtime policy engine in strict mode is class-engine-only.
- Competing engines (PFV3, ActiveSig pipeline, query-driven runtime) are removed from active runtime source.
