# Class Engine `!=` Perf

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 4
- median ours/rls hot-time ratio: 0.712 (target <= 0.8)

## Cases
- N4 target=orders q3: status=ok correctness=PASS ours=2260.059ms rls=2440.580ms ours/rls=0.926 cmp=1/1 key_arity_max=1 cmp_build=5.954 checks/rejects=1500000/0 proj_sig/mask/rid=0/0/0 err=
- N4 target=orders q10: status=ok correctness=PASS ours=1786.029ms rls=3450.779ms ours/rls=0.518 cmp=1/1 key_arity_max=1 cmp_build=5.955 checks/rejects=1500000/0 proj_sig/mask/rid=0/0/0 err=
- N5 target=lineitem q6: status=ok correctness=PASS ours=2681.449ms rls=11687.259ms ours/rls=0.229 cmp=1/1 key_arity_max=2 cmp_build=209.181 checks/rejects=6001215/583 proj_sig/mask/rid=0/0/0 err=
- N5 target=lineitem q9: status=ok correctness=PASS ours=4934.961ms rls=5452.480ms ours/rls=0.905 cmp=/ key_arity_max= cmp_build= checks/rejects=/ proj_sig/mask/rid=// err=
