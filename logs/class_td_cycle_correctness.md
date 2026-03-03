# Class Engine TD-Cycle Correctness

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 4
- PASS: 4, FAIL: 0, ERROR: 0

## Cases
- TDC1 q6: status=PASS ours=(1,72e423cfce83f2c54868729578df9e8e) gt=(1,72e423cfce83f2c54868729578df9e8e) route(td/tree/rect)=1/0/0 td(w/bags/msg)=1/2/0 proj_sig/mask/rid=0/0/0 reason=
- TDC2 q6: status=PASS ours=(1,673a656c6e10bb92e0e700a6f91175a8) gt=(1,673a656c6e10bb92e0e700a6f91175a8) route(td/tree/rect)=1/0/0 td(w/bags/msg)=2/4/688797 proj_sig/mask/rid=0/0/0 reason=
- TDC2 q1: status=PASS ours=(4,fb85168ab9a273f3e7cd6e0550c6c34a) gt=(4,fb85168ab9a273f3e7cd6e0550c6c34a) route(td/tree/rect)=1/0/0 td(w/bags/msg)=2/4/688797 proj_sig/mask/rid=0/0/0 reason=
- TDR1 q6: status=PASS ours=(1,d37045faa672fde537e2b6c314cce341) gt=(1,d37045faa672fde537e2b6c314cce341) route(td/tree/rect)=0/0/1 td(w/bags/msg)=0/0/0 proj_sig/mask/rid=0/0/0 reason=
