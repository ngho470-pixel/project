# Gate Stage03 tpch0_1

- total_cases: 20
- ok: 16
- timeout: 0
- error: 4
- mismatches_vs_rls_index: 2
- median ours/rls_index ratio: 1.043

## Mismatches
- ours S_C q1: rows=4 gt_rows=4
- ours S_C q6: rows=1 gt_rows=1

## Errors
- ours S_D q1: db_error ERROR:  policy: SCC exact solver budget exceeded target=lineitem vars=5
- ours S_D q3: db_error ERROR:  policy: SCC exact solver budget exceeded target=lineitem vars=5
- ours S_D q6: db_error ERROR:  policy: SCC exact solver budget exceeded target=lineitem vars=5
- ours S_D q10: db_error ERROR:  policy: SCC exact solver budget exceeded target=lineitem vars=5

