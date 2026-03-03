# Stage 5 SAT/Hybrid Completeness

## Scope
Stage 5 changes only SAT/hybrid control flow and theory-learning interface in `custom_filter/policy.cpp`.

Unchanged:
- artifact formats/loaders (`dict/domain`, `rank/domain`, `*_code_base`, `*_ctid`),
- atom semantics for `col op const` and `col op col`,
- permissive/restrictive composition,
- propagation math (except conflict surfacing),
- correctness oracle (RLS-with-index hashes).

## 1) OR selectors are now explicit SAT decisions

### Encoding
- OR selector metadata:
  - `OrSelectorBinding` at `custom_filter/policy.cpp:367`
  - `CnfBuildInfo` at `custom_filter/policy.cpp:372`
- Selector implications are added while building Tseitin CNF:
  - `cnf_add_implication_lit_to_expr(...)` at `custom_filter/policy.cpp:382`
  - OR-node handling in `build_formula_cnf_tseitin_rec(...)` at `custom_filter/policy.cpp:399`
  - For each binary OR node `z = (a OR b)`, selector `s_z` is created and:
    - `s_z => a`
    - `!s_z => b`
  - Concrete clause insertion is at `custom_filter/policy.cpp:435` and `custom_filter/policy.cpp:436`.

### Runtime solve path
- Full formula CNF is built (with selectors) in `eval_formula_root_bits(...)`:
  - `build_formula_cnf_tseitin(...)` call at `custom_filter/policy.cpp:4851`.
- SAT solve loop uses cvc5 incremental solving:
  - `solve_with_assumptions({})` at `custom_filter/policy.cpp:4894`.

### Model -> conjunction extraction
- Deterministic child pick is removed.
- Term extraction follows selector assignments:
  - `extract_term_from_selector_model(...)` at `custom_filter/policy.cpp:4611`.
- Selector decisions are collected per model:
  - lambda `collect_selector_decision_lits` at `custom_filter/policy.cpp:4868`.

## 2) Theory-lemma learning is now propagation-conflict driven

### Conflict surfacing from propagation
- `propagate_clause(...)` now returns conflict flag via `out_conflict`:
  - signature at `custom_filter/policy.cpp:3997`
  - conflict flag writes across pruning/fixpoint checks, e.g. `custom_filter/policy.cpp:4152`, `custom_filter/policy.cpp:4243`, `custom_filter/policy.cpp:4332`.
- `eval_term_conjunction_bits(...)` propagates this to formula-level evaluation:
  - signature at `custom_filter/policy.cpp:4691`
  - propagation call at `custom_filter/policy.cpp:4779`.

### Learned clause shape
- On propagation conflict, runtime logs and learns a selector-decision clause:
  - conflict branch at `custom_filter/policy.cpp:4949`
  - learned clause application via `block_decision_clause(...)` at `custom_filter/policy.cpp:4661` and call sites `custom_filter/policy.cpp:4951`, `custom_filter/policy.cpp:4980`.
- Clause form is coarse but sound:
  - if current decision literals are `[l1, l2, ...]`, assert `(!l1 OR !l2 OR ...)`.

## 3) Exact model-enumeration union semantics

- Loop continues SAT model enumeration until UNSAT:
  - `for (;;) { ... solve ... }` at `custom_filter/policy.cpp:4892`.
- For each model:
  - compute `Allow(T|M)` from existing term propagation/projection path,
  - OR-union into global target bits at `custom_filter/policy.cpp:4959`.
- Blocking is on decision literals (selectors), not full incidental model:
  - `block_decision_clause(...)` calls in conflict and non-conflict branches.
- Safe early stop kept only for provably full target allow:
  - `is_target_fully_allowed()` and break at `custom_filter/policy.cpp:4976`.

## 4) Stage 5 validation

Validation artifacts:
- `logs/stage5_correctness.csv`
- `logs/stage5_correctness.md`

Stage1-Stage3 + toy suite reruns remained PASS, and two new Stage5 checks were added:

1. `or_selector_union_regression`
- policy has two satisfiable OR branches with different target-row sets.
- verified:
  - combined result equals union of branch-only results,
  - ours matches RLS hash/count,
  - selector assignments observed in both directions (`selector_signs={... [-1, 1]}`), proving SAT-choice coverage over OR.
- This is the Stage5 guard that fails Stage4 behavior (no selector-decision trace/coverage).

2. `propagation_conflict_lemma`
- policy includes one unsatisfiable OR branch and one satisfiable branch.
- verified:
  - ours matches RLS hash/count,
  - at least one `policy: theory_lemma_conflict` notice is emitted (`conflict_lemma_hits=1`), showing conflict-triggered learning.

