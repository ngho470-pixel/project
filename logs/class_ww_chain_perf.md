# Class Engine Witness-Witness Chain Comparator Perf

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 2
- median ours/rls hot-time ratio: 0.381 (target <= 0.85)

## Cases
- C1 target=partsupp q9: status=ok correctness=PASS ours=2561.033ms rls=7771.633ms ours/rls=0.330 chain(total/supported/steps/build_ms/check/reject)=1/1/4/174.621/12468/12347 proj_sig/mask/rid=0/0/0 err=
- C2 target=partsupp q9: status=ok correctness=PASS ours=2561.253ms rls=5933.978ms ours/rls=0.432 chain(total/supported/steps/build_ms/check/reject)=1/1/4/173.253/12468/12293 proj_sig/mask/rid=0/0/0 err=
