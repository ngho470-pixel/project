# Class Engine TD-Cycle Scan-Cut Perf

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 4
- median ours/rls hot-time ratio: 0.662 (target <= 0.75)

## Cases
- TDC1 target=lineitem q6: status=ok correctness=PASS ours=4848.882ms rls=9789.469ms ours/rls=0.495 route(td/rect)=1/0 empty(mode_seen/tables/short/ms)=0/0/0/0.000 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=1/2/0/0/0/97.217/33.577/28.746/1/0/1597194/1597194/0/0/0/22.592/0/111.062/132.684 proj_sig/mask/rid=0/0/0 err=
- TDC2 target=lineitem q1: status=ok correctness=PASS ours=2199.411ms rls=2650.684ms ours/rls=0.830 route(td/rect)=1/0 empty(mode_seen/tables/short/ms)=0/0/0/0.000 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=2/4/184536/3244160/184536/30.005/12.677/48.530/2/4879213/4902468/23255/0/180038/3145792/29.007/0/0.924/42.730 proj_sig/mask/rid=0/0/0 err=
- TDR1 target=lineitem q6: status=ok correctness=PASS ours=2741.910ms rls=11626.624ms ours/rls=0.236 route(td/rect)=0/1 empty(mode_seen/tables/short/ms)=0/0/0/0.000 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=0/0/0/0/0/0.000/0.000/0.000/0/0/0/0/0/0/0/0.000/0/0.000/0.000 proj_sig/mask/rid=0/0/0 err=
- TDC3 target=lineitem q1: status=fail correctness=FAIL ours=2380.134ms rls=2530.312ms ours/rls=0.941 route(td/rect)=1/0 empty(mode_seen/tables/short/ms)=1/1/1/0.000 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=2/4/539/6596/539/0.121/0.054/93.408/2/4809295/4809971/676/0/515/6244/73.341/0/0.671/0.190 proj_sig/mask/rid=0/0/0 err=TDC3 ratio 0.941 > 0.85
