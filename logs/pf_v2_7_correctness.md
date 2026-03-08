# PF-V2.7 Correctness

- db: `tpch1`
- mode: `strict_mode=on`, `query_driven_mode=off`, `policy_first_v2=on`, `policy_first_v2_force=on`
- cases: 8
- result: PASS=8 FAIL=0 ERROR=0

## Cases
- P29 target=lineitem q1: PASS ours=4/061aaec9134642d9a8747af58b3ad177 gt=4/061aaec9134642d9a8747af58b3ad177 cmp=1/1 key_arity_max=2 key2(entries/build/lookups)=800000/185.274/6001215 proj_sig/mask/rid=0/0/0 reason=
- P29 target=lineitem q6: PASS ours=1/d37045faa672fde537e2b6c314cce341 gt=1/d37045faa672fde537e2b6c314cce341 cmp=1/1 key_arity_max=2 key2(entries/build/lookups)=800000/182.516/6001215 proj_sig/mask/rid=0/0/0 reason=
- P29 target=lineitem q9: PASS ours=175/8cd7dd515f89827a4f7d3b902b4db258 gt=175/8cd7dd515f89827a4f7d3b902b4db258 cmp=1/1 key_arity_max=2 key2(entries/build/lookups)=800000/183.323/6001215 proj_sig/mask/rid=0/0/0 reason=
- P29F target=lineitem q6: PASS ours=1/0853e9979e0c31547e1863b1e5ef0dbe gt=1/0853e9979e0c31547e1863b1e5ef0dbe cmp=1/1 key_arity_max=2 key2(entries/build/lookups)=400310/92.255/5623381 proj_sig/mask/rid=0/0/0 reason=
- P29F target=lineitem q9: PASS ours=175/0264ed980f00a55018ac49596172613c gt=175/0264ed980f00a55018ac49596172613c cmp=1/1 key_arity_max=2 key2(entries/build/lookups)=400310/92.449/5623381 proj_sig/mask/rid=0/0/0 reason=
- P29T target=lineitem q1: PASS ours=4/afb089aa179965d9244f97b84e106e13 gt=4/afb089aa179965d9244f97b84e106e13 cmp=1/1 key_arity_max=2 key2(entries/build/lookups)=800000/184.712/3274126 proj_sig/mask/rid=0/0/0 reason=
- P29T target=lineitem q6: PASS ours=1/d37045faa672fde537e2b6c314cce341 gt=1/d37045faa672fde537e2b6c314cce341 cmp=1/1 key_arity_max=2 key2(entries/build/lookups)=800000/184.280/3274126 proj_sig/mask/rid=0/0/0 reason=
- P29G target=lineitem q6: PASS ours=1/542c5a0d7f7601f97afb0a68497891b1 gt=1/542c5a0d7f7601f97afb0a68497891b1 cmp=1/1 key_arity_max=2 key2(entries/build/lookups)=800000/186.589/6001215 proj_sig/mask/rid=0/0/0 reason=
