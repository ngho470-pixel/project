# Class Engine tpch1 Q2/Q21 Matrix

- db: `tpch1`
- queries: `2,21,1,6`
- mode: `strict_mode=on`, `query_driven_mode=off`
- cases: 2
- status: ok=1 fail=0 error=1

## Cases
- set=A pids=1 q2: status=ok correctness=PASS route=- route_summary=- ours=477/85a4897fccad69361b498bb20d2df030 gt=477/85a4897fccad69361b498bb20d2df030 cmp_total/supported/key_arity=// invariants(sig/mask/rid)=// reason=-
- set=A pids=1 q21: status=ERROR correctness=ERROR route=single_hub route_summary=single_hub:2 ours=/ gt=/ cmp_total/supported/key_arity=0/0/0 invariants(sig/mask/rid)=0/0/0 reason=ERROR:  canceling statement due to statement timeout; ERROR:  canceling statement due to statement timeout; ERROR:  canceling statement due to statement timeout
