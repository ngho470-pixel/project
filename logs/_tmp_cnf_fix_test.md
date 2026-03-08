# Class Engine Full-Language Correctness

- db: `tpch1`
- policy_range: `1..1`
- queries: `1`
- mode: `strict_mode=on`
- cases: 1
- status: ok=0 fail=0 error=1
- route_counts(total_terms_observed): `{}`
- rows_with_route_reject_reason: 0

## Cases
- policy=1 target=lineitem q1: status=ERROR correctness=ERROR route=- route_summary=- ours=/ gt=3/734fbc0d832cca9145f1130f7ba6d4d6 invariants(sig/mask/rid)=-/-/- reason=ERROR:  policy: cvc5 CNF init failed: Invalid kind 'AND', expected Terms with kind AND must have at least 2 children and at most 67108863 children (the one under construction has 1); ERROR:  policy: cvc5 CNF init failed: Invalid kind 'AND', expected Terms with kind AND must have at least 2 children and at most 67108863 children (the one under construction has 1)
