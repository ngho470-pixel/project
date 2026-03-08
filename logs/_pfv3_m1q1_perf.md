# PFV3.0b26-debug tpch1 Perf

- db: `tpch1`
- query_ids: `1 3 6 13 22`
- mode: `strict_mode=on`, `query_driven_mode=off`, `pfv3=on`, `pfv3_force=on`, `pfv3_allow_fallback=off`
- hygiene: each case begins with `python3 scripts/pg_hygiene.py --db tpch1 --kill-nonidle --fail-loud`

## Hygiene / Run IDs
- M1: hygiene=no non-idle backends remaining run_id=cf_8fe916a3410edf4c429b files_table=public.cf_files_cf_8fe916a3410edf4c429b

- cases: 1
- median ours/rls hot-time ratio: 10.744

## Comparator Placeholder (Policies 21-30)
- Policies `21–30` are comparator policies (`col θ col`). PFV3.0b-2 does not support these yet; this report intentionally measures only policy sets drawn from `1–20`.

## Cases
- M1 q1: status=ok correctness=FAIL route=pfv3_solver fallback=0 td_bags/width=231/1 factor_rows=633887720 factor_tuples=322821315 msg_tuples=13972396 allowed_target=682754 target_nrows=6001215 target_rows(scan/allow/stamp)=7501215/158988/158988 stamp_passes=2 dp_ms=306064.388 stamp_ms=19513.797 pfv3_used_bins=0 bin_slices/intersections/rids=0/0/0 proj_sig/mask/rid=0/0/0 ours=389300.316ms rls=36233.091ms ours/rls=10.744 reason=pfv3_stamp_passes=2
