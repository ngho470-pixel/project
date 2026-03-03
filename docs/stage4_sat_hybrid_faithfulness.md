# Stage 4 SAT/Hybrid Faithfulness

## Scope
Stage 4 changes only the runtime SAT/hybrid control structure in `custom_filter/policy.cpp`.

Unchanged:
- artifact format and loaders (`dict/domain`, `rank/domain`, `*_code_base`, `*_ctid`),
- operator semantics for `=, !=, <, <=, >, >=`,
- permissive/restrictive composition,
- correctness oracle (RLS-with-index rowcount/hash).

## What Changed

### 1) Runtime now solves full formula CNF (Tseitin), not OR-node-only SAT
- CNF builder used in runtime path: `build_formula_cnf_tseitin(...)` at `custom_filter/policy.cpp:418` and call site `custom_filter/policy.cpp:4792`.
- SAT solve loop still uses cvc5 incremental solving (`solve_with_assumptions({})`) at `custom_filter/policy.cpp:4817`.

### 2) CNF variable mapping
- Leaf policy atoms remain `y_i` variables from AST (positive var ids).
- Internal AND/OR nodes get Tseitin vars via CNF construction (`cnf_add_tseitin_and_equiv`, `cnf_add_tseitin_or_equiv`) at `custom_filter/policy.cpp:345`, `custom_filter/policy.cpp:336`.
- Root truth is enforced by unit clause from the Tseitin build (`build_formula_cnf_tseitin`).

### 3) SAT model -> conjunction term used by theory engine
- SAT model truth for AST nodes is reconstructed by `ast_model_value(...)` at `custom_filter/policy.cpp:4509`.
- One implied conjunction term is extracted by `extract_term_from_sat_model(...)` at `custom_filter/policy.cpp:4558`:
  - AND: include both true children,
  - OR: choose one true child deterministically,
  - VAR: include atom if true.
- Term evaluation reuses existing propagation+projection by `eval_term_conjunction_bits(...)` call in `eval_formula_root_bits` at `custom_filter/policy.cpp:4857`.

### 4) Model enumeration and union semantics
- For each SAT model:
  - compute `Allow(T|M)` bits from the term,
  - OR-union into global `Allow(T)` at `custom_filter/policy.cpp:4868`.
- Iteration continues until SAT UNSAT.
- Safe early stop is retained when target is already fully allowed (`is_target_fully_allowed`) at `custom_filter/policy.cpp:4805`, `custom_filter/policy.cpp:4885`.

### 5) Theory-lemma hook on conflict
- Added `block_term_clause(...)` at `custom_filter/policy.cpp:4616`.
- If a conjunction contributes no target rows (`term_has_rows == false`), runtime learns and asserts clause:
  - `¬a1 ∨ ¬a2 ∨ ...` over that term’s atom literals,
  - implemented at `custom_filter/policy.cpp:4878` to `custom_filter/policy.cpp:4881`.
- This is sound for target-allow computation: it only prunes assignments containing an already-proven non-contributing conjunction.

### 6) Exact-mode cap handling
- Removed `term_cap` truncation in model enumeration (no partial allow-set return).
- Removed cyclic propagation hard cap in exact path; cyclic propagation now runs to fixpoint (`Cyclic fallback: iterate to exact fixpoint`) at `custom_filter/policy.cpp:4196`.

## Notes on Unchanged Theory Components
- Comparator pruning and rank usage remain unchanged in:
  - `apply_clause_comparators(...)` and rank checks at `custom_filter/policy.cpp:3655`, `custom_filter/policy.cpp:3192`.
- Scan-time enforcement remains CTID bitmap membership in `custom_filter/custom_filter.c:111` and `custom_filter/custom_filter.c:3473`.

## Validation Run
After Stage 4 changes, reran unchanged verification flows:
- `scripts/stage1_correctness_verify.py`
- `scripts/stage2_correctness_verify.py`
- `scripts/stage3_correctness_verify.py`
- `scripts/toy_glassbox_audit.py`

Aggregated results are in:
- `logs/stage4_correctness.csv`
- `logs/stage4_correctness.md`
