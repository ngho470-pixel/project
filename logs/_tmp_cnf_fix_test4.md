# Class Engine Full-Language Correctness

- db: `tpch1`
- policy_range: `1..1`
- queries: `1`
- mode: `strict_mode=on`
- cases: 1
- status: ok=1 fail=0 error=0
- route_counts(total_terms_observed): `{'single_hub': 2}`
- rows_with_route_reject_reason: 0

## Cases
- policy=1 target=lineitem q1: status=ok correctness=PASS route=single_hub route_summary=single_hub:2 ours=3/734fbc0d832cca9145f1130f7ba6d4d6 gt=3/734fbc0d832cca9145f1130f7ba6d4d6 invariants(sig/mask/rid)=0/0/0 reason=-
