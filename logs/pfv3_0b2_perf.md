# PFV3.0b-2 Perf Smoke

- db: `tpch1`
- mode: `strict_mode=on`, `query_driven_mode=off`, `pfv3=on`, `pfv3_force=on`, `pfv3_allow_fallback=off`
- cases: 3
- median ours/rls: 2.279

## Cases
- P0S target=lineitem q1: status=ok correctness=PASS ours=3434.855ms rls=1506.926ms ours/rls=2.279 td_bags/width=1/0 factor_tuples=1 msg_tuples=0 allowed_target=1 stamp_rows=468252 stamp_ms=96.085 bin_slices/intersections=0/0 proj_sig/mask/rid=0/0/0 reason=
- P0C target=lineitem q3: status=ok correctness=PASS ours=5271.988ms rls=1597.156ms ours/rls=3.301 td_bags/width=2/1 factor_tuples=3029752 msg_tuples=297453 allowed_target=297453 stamp_rows=0 stamp_ms=85.826 bin_slices/intersections=297456/297453 proj_sig/mask/rid=0/0/0 reason=
- P0R target=lineitem q1: status=ok correctness=PASS ours=9157.400ms rls=21446.167ms ours/rls=0.427 td_bags/width=2/1 factor_tuples=1199851 msg_tuples=400086 allowed_target=400086 stamp_rows=0 stamp_ms=806.951 bin_slices/intersections=800174/800172 proj_sig/mask/rid=0/0/0 reason=
