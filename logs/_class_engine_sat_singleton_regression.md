# Class Engine Full-Language Correctness

- db: `tpch1`
- policy_range: `1..1`
- queries: `1,3,6`
- mode: `strict_mode=on`
- cases: 3
- status: ok=3 fail=0 error=0
- route_counts(total_terms_observed): `{'single_hub': 6}`
- rows_with_route_reject_reason: 0

## Cases
- policy=1 target=lineitem q1: status=ok correctness=PASS route=single_hub route_summary=single_hub:2 ours=3/734fbc0d832cca9145f1130f7ba6d4d6 gt=3/734fbc0d832cca9145f1130f7ba6d4d6 invariants(sig/mask/rid)=0/0/0 reason=-
- policy=1 target=lineitem q3: status=ok correctness=PASS route=single_hub route_summary=single_hub:2 ours=11313/9e52402f50f26089a49062bbfaef1534 gt=11313/9e52402f50f26089a49062bbfaef1534 invariants(sig/mask/rid)=0/0/0 reason=-
- policy=1 target=lineitem q6: status=ok correctness=PASS route=single_hub route_summary=single_hub:2 ours=1/a48343de54b0874914799f71b8d6459a gt=1/a48343de54b0874914799f71b8d6459a invariants(sig/mask/rid)=0/0/0 reason=-
