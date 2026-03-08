# Class Engine TD-Cycle Perf

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 3
- median ours/rls hot-time ratio: 0.678

## Cases
- TDC1 target=lineitem q6: status=ok correctness=PASS ours=6597.377ms rls=9729.206ms ours/rls=0.678 route(td/rect)=1/0 td(width/bags/msg/build/dp)=1/2/0/107.669/1491.145 proj_sig/mask/rid=0/0/0 err=
- TDC2 target=lineitem q6: status=ok correctness=PASS ours=10332.002ms rls=2078.715ms ours/rls=4.970 route(td/rect)=1/0 td(width/bags/msg/build/dp)=2/4/688797/0.899/5348.816 proj_sig/mask/rid=0/0/0 err=
- TDR1 target=lineitem q6: status=ok correctness=PASS ours=2741.996ms rls=11777.645ms ours/rls=0.233 route(td/rect)=0/1 td(width/bags/msg/build/dp)=0/0/0/0.000/0.000 proj_sig/mask/rid=0/0/0 err=
