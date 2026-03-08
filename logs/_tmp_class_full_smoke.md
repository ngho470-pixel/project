# Class Engine Full-Language Correctness

- db: `tpch1`
- policy_range: `1..1`
- queries: `1,3,6,13,22`
- mode: `strict_mode=on`
- cases: 5
- status: ok=2 fail=0 error=3
- route_counts(total_terms_observed): `{}`
- rows_with_route_reject_reason: 0

## Cases
- policy=1 target=lineitem q1: status=ERROR correctness=ERROR route=- route_summary=- ours=/ gt=3/734fbc0d832cca9145f1130f7ba6d4d6 invariants(sig/mask/rid)=-/-/- reason=ERROR:  policy: cvc5 CNF init failed: Invalid kind 'AND', expected Terms with kind AND must have at least 2 children and at most 67108863 children (the one under construction has 1); ERROR:  policy: cvc5 CNF init failed: Invalid kind 'AND', expected Terms with kind AND must have at least 2 children and at most 67108863 children (the one under construction has 1)
- policy=1 target=lineitem q3: status=ERROR correctness=ERROR route=- route_summary=- ours=/ gt=11313/9e52402f50f26089a49062bbfaef1534 invariants(sig/mask/rid)=-/-/- reason=ERROR:  policy: cvc5 CNF init failed: Invalid kind 'AND', expected Terms with kind AND must have at least 2 children and at most 67108863 children (the one under construction has 1); ERROR:  policy: cvc5 CNF init failed: Invalid kind 'AND', expected Terms with kind AND must have at least 2 children and at most 67108863 children (the one under construction has 1)
- policy=1 target=lineitem q6: status=ERROR correctness=ERROR route=- route_summary=- ours=/ gt=1/a48343de54b0874914799f71b8d6459a invariants(sig/mask/rid)=-/-/- reason=ERROR:  policy: cvc5 CNF init failed: Invalid kind 'AND', expected Terms with kind AND must have at least 2 children and at most 67108863 children (the one under construction has 1); ERROR:  policy: cvc5 CNF init failed: Invalid kind 'AND', expected Terms with kind AND must have at least 2 children and at most 67108863 children (the one under construction has 1)
- policy=1 target=lineitem q13: status=ok correctness=PASS route=- route_summary=- ours=42/6789fe4f627c452d04e01d4e1a4c0384 gt=42/6789fe4f627c452d04e01d4e1a4c0384 invariants(sig/mask/rid)=-/-/- reason=-
- policy=1 target=lineitem q22: status=ok correctness=PASS route=- route_summary=- ours=7/8fb9a5eb160efdc9d8879b2ad503adfe gt=7/8fb9a5eb160efdc9d8879b2ad503adfe invariants(sig/mask/rid)=-/-/- reason=-
