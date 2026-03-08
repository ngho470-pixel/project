# Class Engine TD-Cycle Correctness

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 5
- PASS: 5, FAIL: 0, ERROR: 0

## Cases
- TDC1 q6: status=PASS ours=(1,72e423cfce83f2c54868729578df9e8e) gt=(1,72e423cfce83f2c54868729578df9e8e) route(td/tree/rect)=1/0/0 td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce)=1/2/0/0/0/105.523/36.549/0.000 proj_sig/mask/rid=0/0/0 reason=
- TDC2 q6: status=PASS ours=(1,673a656c6e10bb92e0e700a6f91175a8) gt=(1,673a656c6e10bb92e0e700a6f91175a8) route(td/tree/rect)=1/0/0 td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce)=2/4/688797/12976256/688797/374.365/49.504/0.000 proj_sig/mask/rid=0/0/0 reason=
- TDC2 q1: status=PASS ours=(4,fb85168ab9a273f3e7cd6e0550c6c34a) gt=(4,fb85168ab9a273f3e7cd6e0550c6c34a) route(td/tree/rect)=1/0/0 td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce)=2/4/688797/12976256/688797/374.319/49.432/0.000 proj_sig/mask/rid=0/0/0 reason=
- TDR1 q6: status=PASS ours=(1,d37045faa672fde537e2b6c314cce341) gt=(1,d37045faa672fde537e2b6c314cce341) route(td/tree/rect)=0/0/1 td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce)=0/0/0/0/0/0.000/0.000/0.000 proj_sig/mask/rid=0/0/0 reason=
- TDC3 q1: status=PASS ours=(0,d41d8cd98f00b204e9800998ecf8427e) gt=(0,d41d8cd98f00b204e9800998ecf8427e) route(td/tree/rect)=1/0/0 td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce)=2/4/3325/40028/3325/246.006/0.327/0.000 proj_sig/mask/rid=0/0/0 reason=
