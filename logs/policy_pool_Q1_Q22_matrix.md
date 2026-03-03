# Policy Pool Q1..Q22 Matrix

- status: `INCOMPLETE`
- reason: `statement_timeout=0` exhaustive run over `S1..S9 x Q1..Q22` did not finish in practical wall time and the first implementation of the runner only writes output at completion.
- command used:

```bash
python3 scripts/policy_pool_q1_q22_matrix.py --db tpch1 --statement-timeout 0
```

## Current blockers captured
- Strict route rejection exists for policy `19` even in single-policy smoke: `logs/policy_pool_single_policy_smoke.md`
- Q21 behavior debug is captured in:
  - `logs/q21_plain_explain.md`
  - `logs/q21_rls_explain.md`
  - `logs/q21_ours_explain.md`
  - `logs/q21_wrapper_audit.txt`
  - `logs/q21_timeout_rootcause.md`
