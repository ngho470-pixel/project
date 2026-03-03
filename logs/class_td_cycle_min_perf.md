# Class Engine TD-Cycle Minimization Perf

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 4
- median ours/rls hot-time ratio: 0.670 (target <= 0.75)

## Cases
- TDC1 target=lineitem q6: status=ok correctness=PASS ours=4819.773ms rls=9609.263ms ours/rls=0.502 route(td/rect)=1/0 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=1/2/0/0/0/97.148/32.039/27.783/1/0/1597194/1597194/0/0/0/21.517/0/108.592/131.073 proj_sig/mask/rid=0/0/0 err=
- TDC2 target=lineitem q1: status=ok correctness=PASS ours=2199.379ms rls=2620.683ms ours/rls=0.839 route(td/rect)=1/0 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=2/4/184536/3244160/184536/30.111/11.869/46.740/2/4879213/4902468/23255/0/180038/3145792/27.137/0/0.894/42.028 proj_sig/mask/rid=0/0/0 err=
- TDR1 target=lineitem q6: status=ok correctness=PASS ours=2741.705ms rls=11687.042ms ours/rls=0.235 route(td/rect)=0/1 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=0/0/0/0/0/0.000/0.000/0.000/0/0/0/0/0/0/0/0.000/0/0.000/0.000 proj_sig/mask/rid=0/0/0 err=
- TDC3 target=lineitem q1: status=fail correctness=FAIL ours=2380.144ms rls=2500.175ms ours/rls=0.952 route(td/rect)=1/0 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)=2/4/539/6596/539/0.109/0.049/93.658/2/4809295/4809971/676/0/515/6244/74.038/0/0.664/0.173 proj_sig/mask/rid=0/0/0 err=TDC3 ratio 0.952 > 0.85
