# Class Engine TD-Cycle Perf

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 4
- median ours/rls hot-time ratio: 0.736

## Cases
- TDC1 target=lineitem q6: status=ok correctness=PASS ours=4940.521ms rls=9790.171ms ours/rls=0.505 route(td/rect)=1/0 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce/build/dp)=1/2/0/0/0/106.734/36.373/0.000/108.866/145.150 proj_sig/mask/rid=0/0/0 err=
- TDC2 target=lineitem q1: status=ok correctness=PASS ours=2560.780ms rls=2650.808ms ours/rls=0.966 route(td/rect)=1/0 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce/build/dp)=2/4/688797/12976256/688797/376.322/49.930/0.000/0.899/453.454 proj_sig/mask/rid=0/0/0 err=
- TDR1 target=lineitem q6: status=ok correctness=PASS ours=2742.168ms rls=11556.789ms ours/rls=0.237 route(td/rect)=0/1 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce/build/dp)=0/0/0/0/0/0.000/0.000/0.000/0.000/0.000 proj_sig/mask/rid=0/0/0 err=
- TDC3 target=lineitem q1: status=ok correctness=PASS ours=2560.717ms rls=2530.287ms ours/rls=1.012 route(td/rect)=1/0 td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce/build/dp)=2/4/3325/40028/3325/246.849/0.324/0.000/0.646/272.375 proj_sig/mask/rid=0/0/0 err=
