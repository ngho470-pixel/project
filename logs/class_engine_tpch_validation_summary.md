# Class Engine Validation Summary (tpch1)

## Scope Executed
- strict mode: `on`
- query-driven mode: `off`
- class-engine strict routing only

## 1) Key-Arity Static Report (compiled-plan driven)
- `logs/policy_pool_key_arity_static.csv`
- `logs/policy_pool_key_arity_static.md`
- Result:
  - `max_cmp_key_arity = 2`
  - `max_hub_key_arity = 1`
  - no policy with key arity `>2`
  - policy `29` is the only arity-2 comparator case

## 2) Key-Arity Dynamic Report (mapping fixed)
- `logs/class_engine_key_arity_report.csv`
- `logs/class_engine_key_arity_report.md`
- Mapping bug (`partsupp/supplier` wrong query-id lookup) is fixed.
- Policies `20/24/25/28/30` are exercised on mapped queries.
- Remaining strict error:
  - `policy=19`: `class_engine unsupported term shape` (route `reject`)

## 3) Single-Policy Smoke (1..30, mapped query per target)
- `logs/policy_pool_single_policy_smoke.csv`
- `logs/policy_pool_single_policy_smoke.md`
- Result:
  - `29/30` policies: `PASS` vs `rls_with_index` (rows + hash)
  - `policy=19`: strict fail-loud reject (unsupported shape)
- Invariants:
  - all successful strict rows show `proj_sig_count=0`, `proj_mask_or_ops=0`, `proj_rid_iters=0`

## 4) Q21 Timeout Debug (policy-set `{1}`)
- `logs/q21_plain_explain.md`
- `logs/q21_rls_explain.md`
- `logs/q21_ours_explain.md`
- `logs/q21_wrapper_audit.txt`
- `logs/q21_timeout_rootcause.md`
- Findings:
  - Plain and Ours timed out under bounded `statement_timeout=10min` during `EXPLAIN ANALYZE`.
  - `rls_with_index` completed (`~1.65s` in captured run).
  - Wrapper audit shows multiple `lineitem` aliases/scans (`scanrelid 2/5/6`) are wrapped by CustomScan instrumentation.

## 5) Full S1..S9 x Q1..Q22 Matrix
- Requested exhaustive run command was started:
  - `python3 scripts/policy_pool_q1_q22_matrix.py --db tpch1 --statement-timeout 0`
- It was stopped due impractical unbounded wall-time before checkpoint write (current runner writes outputs on completion).
- Placeholder status files:
  - `logs/policy_pool_Q1_Q22_matrix.csv`
  - `logs/policy_pool_Q1_Q22_matrix.md`

## Minimal Failing Repro
```bash
cd /tmp/z3_lab/project
python3 scripts/policy_pool_single_policy_smoke.py --db tpch1 --policy-min 19 --policy-max 19 --statement-timeout 0
```
Expected:
- strict fail-loud with `route=reject` and reason `class_engine unsupported term shape`.
