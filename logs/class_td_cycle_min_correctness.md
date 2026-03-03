# Class Engine TD-Cycle Minimization Correctness

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 5
- PASS: 5, FAIL: 0, ERROR: 0

## Cases
- TDC1 q6: status=PASS ours=(1,72e423cfce83f2c54868729578df9e8e) gt=(1,72e423cfce83f2c54868729578df9e8e) route(td/tree/rect)=1/0/0 td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm)=1/2/0/0/0/94.779/31.348/28.587/1/0/1597194/1597194/0/0/0/22.424/0 proj_sig/mask/rid=0/0/0 reason=
- TDC2 q6: status=PASS ours=(1,673a656c6e10bb92e0e700a6f91175a8) gt=(1,673a656c6e10bb92e0e700a6f91175a8) route(td/tree/rect)=1/0/0 td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm)=2/4/184536/3244160/184536/30.219/11.912/46.777/2/4879213/4902468/23255/0/180038/3145792/27.196/0 proj_sig/mask/rid=0/0/0 reason=
- TDC2 q1: status=PASS ours=(4,fb85168ab9a273f3e7cd6e0550c6c34a) gt=(4,fb85168ab9a273f3e7cd6e0550c6c34a) route(td/tree/rect)=1/0/0 td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm)=2/4/184536/3244160/184536/30.143/11.907/48.272/2/4879213/4902468/23255/0/180038/3145792/28.913/0 proj_sig/mask/rid=0/0/0 reason=
- TDR1 q6: status=PASS ours=(1,d37045faa672fde537e2b6c314cce341) gt=(1,d37045faa672fde537e2b6c314cce341) route(td/tree/rect)=0/0/1 td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm)=0/0/0/0/0/0.000/0.000/0.000/0/0/0/0/0/0/0/0.000/0 proj_sig/mask/rid=0/0/0 reason=
- TDC3 q1: status=PASS ours=(0,d41d8cd98f00b204e9800998ecf8427e) gt=(0,d41d8cd98f00b204e9800998ecf8427e) route(td/tree/rect)=1/0/0 td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm)=2/4/539/6596/539/0.108/0.050/92.930/2/4809295/4809971/676/0/515/6244/73.336/0 proj_sig/mask/rid=0/0/0 reason=
