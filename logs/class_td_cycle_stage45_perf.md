# Class Engine TD-Cycle Scan-Cut Perf

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 4
- median ours/rls hot-time ratio: 0.922 (target <= 0.75)

## Cases
- TDC1 target=lineitem q6: status=ok correctness=PASS ours=5000.772ms rls=9789.502ms ours/rls=0.511 route(td/rect)=1/0 empty(mode_seen/tables/short/ms)=0/0/0/0.000 query_sc(empty/reason/ms/hits)=0/no_empty_allow/0.000/0 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=1/2/0/0/0/102.651/32.211/128.667/1/2802/1597194/1594392//////107.385/136.482 proj_sig/mask/rid=0/0/0 err=
- TDC2 target=lineitem q1: status=fail correctness=FAIL ours=3494.651ms rls=2620.744ms ours/rls=1.333 route(td/rect)=1/0 empty(mode_seen/tables/short/ms)=0/0/0/0.000 query_sc(empty/reason/ms/hits)=0/no_empty_allow/0.000/0 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=2/4/183475/3244160/183475/29.655/12.231/1352.718/2/4879219/4902468/23249//////0.816/41.919 proj_sig/mask/rid=0/0/0 err=TDC2 ratio 1.333 > 0.85
- TDR1 target=lineitem q6: status=ok correctness=PASS ours=2771.672ms rls=11747.314ms ours/rls=0.236 route(td/rect)=0/1 empty(mode_seen/tables/short/ms)=0/0/0/0.000 query_sc(empty/reason/ms/hits)=0/no_empty_allow/0.000/0 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=0/0/0/0/0/0.000/0.000/0.000/0/0/0/0//////0.000/0.000 proj_sig/mask/rid=0/0/0 err=
- TDC3 target=lineitem q1: status=fail correctness=FAIL ours=3554.905ms rls=2500.080ms ours/rls=1.422 route(td/rect)=1/0 empty(mode_seen/tables/short/ms)=0/0/0/0.000 query_sc(empty/reason/ms/hits)=1/inner_only_empty/0.000/1 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=2/4/40/608/40/0.020/0.005/1319.354/2/4809814/4809971/157//////0.588/0.031 proj_sig/mask/rid=0/0/0 err=TDC3 ratio 1.422 > 0.85

- PERF_GATE_FAIL: median ours/rls 0.922 > 0.75
