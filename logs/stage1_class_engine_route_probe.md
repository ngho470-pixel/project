# Stage1 Class-Engine Route Probe

- source CSVs: `logs/pf_v2_6_perf.csv`, `logs/pf_v2_7_perf.csv`
- objective: prove strict runs are on class-engine path and not signature projection

## pf_v2_6_perf.csv
- rows: `7`
- rows with `pf2_terms_tree>0`: `7`
- rows with `pf2_cmp_supported>0`: `7`
- rows with `pf2_cmp_key2_entries>0`: `2`
- invariant violations (`proj_sig_count|proj_mask_or_ops|proj_rid_iters != 0`): `0`

## pf_v2_7_perf.csv
- rows: `6`
- rows with `pf2_terms_tree>0`: `0`
- rows with `pf2_cmp_supported>0`: `6`
- rows with `pf2_cmp_key2_entries>0`: `6`
- invariant violations (`proj_sig_count|proj_mask_or_ops|proj_rid_iters != 0`): `0`
