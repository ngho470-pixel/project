# Class Engine TD-Cycle Scan-Cut Correctness

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 5
- PASS: 5, FAIL: 0, ERROR: 0

## Cases
- TDC1 q6: status=PASS ours=(1,72e423cfce83f2c54868729578df9e8e) gt=(1,72e423cfce83f2c54868729578df9e8e) route(td/tree/rect)=1/0/0 empty(mode_seen/tables/short/ms)=0/0/0/0.000 td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm)=1/2/0/0/0/103.044/32.059/126.944/1/2802/1597194/1594392///// proj_sig/mask/rid=0/0/0 reason=
- TDC2 q6: status=PASS ours=(1,673a656c6e10bb92e0e700a6f91175a8) gt=(1,673a656c6e10bb92e0e700a6f91175a8) route(td/tree/rect)=1/0/0 empty(mode_seen/tables/short/ms)=0/0/0/0.000 td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm)=2/4/183475/3244160/183475/30.764/11.568/1349.005/2/4879219/4902468/23249///// proj_sig/mask/rid=0/0/0 reason=
- TDC2 q1: status=PASS ours=(4,fb85168ab9a273f3e7cd6e0550c6c34a) gt=(4,fb85168ab9a273f3e7cd6e0550c6c34a) route(td/tree/rect)=1/0/0 empty(mode_seen/tables/short/ms)=0/0/0/0.000 td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm)=2/4/183475/3244160/183475/30.581/11.751/1340.228/2/4879219/4902468/23249///// proj_sig/mask/rid=0/0/0 reason=
- TDR1 q6: status=PASS ours=(1,d37045faa672fde537e2b6c314cce341) gt=(1,d37045faa672fde537e2b6c314cce341) route(td/tree/rect)=0/0/1 empty(mode_seen/tables/short/ms)=0/0/0/0.000 td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm)=0/0/0/0/0/0.000/0.000/0.000/0/0/0/0///// proj_sig/mask/rid=0/0/0 reason=
- TDC3 q1: status=PASS ours=(0,d41d8cd98f00b204e9800998ecf8427e) gt=(0,d41d8cd98f00b204e9800998ecf8427e) route(td/tree/rect)=1/0/0 empty(mode_seen/tables/short/ms)=1/1/1/0.000 td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm)=2/4/40/608/40/0.020/0.005/1317.240/2/4809814/4809971/157///// proj_sig/mask/rid=0/0/0 reason=
