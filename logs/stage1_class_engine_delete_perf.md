# Stage1 Class-Engine Delete Perf

- source: drona `/tmp/z3_lab/project` (synced to local)
- strict invariants audited from perf CSVs

## Perf Suites
- `pf_v2_6_perf.csv`: rows=7, median ours/rls=`0.502`, invariant_violations=`0`, cmp_supported_rows=`7`
- `pf_v2_7_perf.csv`: rows=6, median ours/rls=`0.367`, invariant_violations=`0`, cmp_supported_rows=`6`

## Invariants
- `proj_sig_count=0`, `proj_mask_or_ops=0`, `proj_rid_iters=0` for all rows in both perf suites.
- Comparator summary path is exercised (`pf2_cmp_supported>0`) in measured rows.
