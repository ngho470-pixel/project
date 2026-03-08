# Gate Stage03 tpch0_1

- total_cases: 40
- ok: 38
- timeout: 0
- error: 2
- mismatches_vs_rls_index: 10
- median ours/rls_index ratio: 1.447

## Mismatches
- ours S_C q1: rows=4 gt_rows=4
- ours S_C q3: rows=563 gt_rows=39
- ours S_C q6: rows=1 gt_rows=1
- ours S_D q1: rows=0 gt_rows=4
- ours S_D q6: rows=1 gt_rows=1
- ours S_D q10: rows=0 gt_rows=49
- ours S_F q1: rows=4 gt_rows=4
- ours S_F q6: rows=1 gt_rows=1
- ours S_G q1: rows=4 gt_rows=3
- ours S_G q6: rows=1 gt_rows=1

## Errors
- ours S_C q10: db_error ERROR:  could not load library "/home/ng_lab/z3/custom_filter/custom_filter.so": /home/ng_lab/z3/custom_filter/custom_filter.so: file too short
- ours S_C q11: db_error ERROR:  could not load library "/home/ng_lab/z3/custom_filter/custom_filter.so": /home/ng_lab/z3/custom_filter/custom_filter.so: file too short

