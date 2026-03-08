# PFV3.0b-2 tpch1 Perf

- db: `tpch1`
- query_ids: `1 3 6 13 22`
- mode: `strict_mode=on`, `query_driven_mode=off`, `pfv3=on`, `pfv3_force=on`, `pfv3_allow_fallback=off`
- hygiene: each case begins with `python3 scripts/pg_hygiene.py --db tpch1 --kill-nonidle --fail-loud`

## Hygiene / Run IDs
- S1: hygiene=no non-idle backends remaining run_id=cf_1498df887ee295cea307 files_table=public.cf_files_cf_1498df887ee295cea307

- cases: 1
- median ours/rls hot-time ratio: n/a

## Comparator Placeholder (Policies 21-30)
- Policies `21–30` are comparator policies (`col θ col`). PFV3.0b-2 does not support these yet; this report intentionally measures only policy sets drawn from `1–20`.

## Cases
- S1 q1: status=error correctness=ERROR route= fallback= td_bags/width=/ factor_rows= factor_tuples= msg_tuples= allowed_target= target_nrows= target_rows(scan/allow/stamp)=// stamp_passes= dp_ms= stamp_ms= pfv3_used_bins= bin_slices/intersections/rids=// proj_sig/mask/rid=// ours=ms rls=ms ours/rls= reason=ERROR:  canceling statement due to user request
