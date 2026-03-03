# Formal Theory Faithfulness Audit + Dead Path Elimination (Coder Prompt)

Task: **Formal Theory Faithfulness Audit + Dead Path Elimination**

## A) Produce `docs/final_theory_faithfulness_audit_v2.md`

Using `docs/final_formal_theory_spec.md` as the authoritative reference:

For each numbered section (`2.x` artifacts, `3.x` evaluation, `4.x` enforcement), list:

- exact source file + function(s)
- exact runtime path (who calls who)
- any deviations (even if perf-only)
- whether deviation is: correctness risk / scope risk / perf-only

You must also produce the single exact-path call graph from the theory spec's \"Exact Path Entry\" section and prove all runtime evaluation dispatch reaches only that path.

Add a "foulplay" checklist with YES/NO + evidence:

- any heuristic truncation?
- any alternate evaluation path still reachable?
- any DFS/backtracking in exact path?
- any legacy operators accepted in strict mode?
- any per-row join materialization?
- any term/model caps still reachable?
- any propagation caps still reachable?
- any old artifact format fallback still reachable?

## B) Eliminate Everything Not in the Exact Path

Cleanup requirement: **if it's not on the formal path, it must go.**

You must identify all alternate/legacy paths and delete them, including:

- old artifact formats (e.g., `CB03`) if not needed
- DNF wrapper paths if not needed
- DFS/backtracking witness search code (must not exist in the codebase at all, not even behind debug flags)
- `IN` / `LIKE` support (must be rejected in strict mode; remove implementation or make unreachable)
- any debug-only evaluator modes / flags / branches not used by harness

Forbidden engineering crutches in strict experimental mode (delete or fail-loud):

- term/model caps
- propagation iteration caps
- \"early stop when good enough\"
- fallback to old artifact formats

If any remain for development use, strict experimental mode must crash loudly when they would trigger.

Remove debug print code not used by profiling harness:

- keep a single unified profiling/logging mechanism (the one used by `fast_sweep_profile_60s.py`)
- remove ad-hoc `NOTICE` spam, leftover diagnostic flags, dead counters

Remove unused structs/functions (dead code):

- compile with `-Wall -Wextra -Werror` and fix unused warnings by deletion, not suppression
- run `nm` / `objdump` or compiler reports to identify unreferenced functions

Deliverable: `docs/dead_code_elimination_report.md` with:

- removed items list
- commit summary
- proof they are unreachable before removal (callgraph or grep evidence)
- proof tests still pass after removal

## C) Validation Gates After Deletion

After cleanup:

- rerun Stage 1-8 suites unchanged (PASS)
- rerun Stage 9 suite for 21-30 (PASS)
- rerun Stage 10R2 correctness (PASS)
- rerun one perf sweep (`fast_sweep_profile_60s.py`) to ensure nothing broke the harness

Add one semantic equivalence guard test/script (CI-safe) that proves pair-bundle pruning is semantically necessary:

- run policy `27` and `29` with pair-bundle pruning enabled (expect PASS vs RLS)
- run the same cases with pair-bundle pruning disabled while keeping marginals-only propagation (expect FAIL vs RLS)
- assert the second mode fails correctness

If multiple projection methods still exist, add an additional same-binary equivalence check for projection outputs; otherwise delete alternate projection paths.

Outputs:

- `logs/final_audit_correctness.csv/.md`
- `logs/final_audit_perf.csv/.md`

## D) Strict Mode Must Be the Default

Set strict mode default **ON** in the harness/config used for experiments.

If strict mode can be disabled for development, it must require an explicit opt-out flag and must be clearly labeled non-experimental.

The benchmark harness must:

- explicitly set strict mode ON
- fail immediately if a non-strict operator is detected
- stamp `NON_EXPERIMENTAL` into logs for any opt-out run
