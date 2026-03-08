# Class Engine TD-Cycle Scan-Cut Perf

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 4
- median ours/rls hot-time ratio: 0.909 (target <= 0.75)

## Cases
- TDC1 target=lineitem q6: status=ok correctness=PASS ours=4940.311ms rls=9668.851ms ours/rls=0.511 route(td/rect)=1/0 empty(mode_seen/tables/short/ms)=0/0/0/0.000 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=1/2/0/0/0/101.038/31.528/127.437/1/2802/1597194/1594392//////108.126/134.190 proj_sig/mask/rid=0/0/0 err=
- TDC2 target=lineitem q1: status=fail correctness=FAIL ours=3464.452ms rls=2651.312ms ours/rls=1.307 route(td/rect)=1/0 empty(mode_seen/tables/short/ms)=0/0/0/0.000 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=2/4/183475/3244160/183475/30.814/11.725/1347.294/2/4879219/4902468/23249//////0.836/42.571 proj_sig/mask/rid=0/0/0 err=TDC2 ratio 1.307 > 0.85
- TDR1 target=lineitem q6: status=ok correctness=PASS ours=2772.303ms rls=11626.622ms ours/rls=0.238 route(td/rect)=0/1 empty(mode_seen/tables/short/ms)=0/0/0/0.000 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=0/0/0/0/0/0.000/0.000/0.000/0/0/0/0//////0.000/0.000 proj_sig/mask/rid=0/0/0 err=
- TDC3 target=lineitem q1: status=fail correctness=FAIL ours=3584.881ms rls=2530.291ms ours/rls=1.417 route(td/rect)=1/0 empty(mode_seen/tables/short/ms)=1/1/1/0.000 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=2/4/40/608/40/0.024/0.007/1302.347/2/4809814/4809971/157//////0.568/0.040 proj_sig/mask/rid=0/0/0 err=TDC3 ratio 1.417 > 0.85

- PERF_GATE_FAIL: median ours/rls 0.909 > 0.75
