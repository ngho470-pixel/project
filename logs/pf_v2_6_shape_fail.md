# PF-V2.6 Shape Fail-Loud

- db: `tpch1`
- mode: `strict_mode=on`, `query_driven_mode=off`, `policy_first_v2=on`, `policy_first_v2_force=on`

## Cases
- F_XNE: PASS :: cross-table != comparator unsupported in PF-V2.6 :: error=`ERROR:  policy: PF-V2 path unsupported term shape on target=orders HINT:  disable custom_filter.policy_first_v2_force or disable custom_filter.policy_first_v2`
- F_K3: PASS :: cross-table comparator separator key arity > 2 (customer-orders-lineitem-supplier chain) :: error=`ERROR:  policy: PF-V2 path unsupported term shape on target=supplier HINT:  disable custom_filter.policy_first_v2_force or disable custom_filter.policy_first_v2`
- F_CYCLE: PASS :: cyclic factor graph with cross-table comparator (policy29 shape) :: error=`ERROR:  policy: PF-V2 path unsupported term shape on target=lineitem HINT:  disable custom_filter.policy_first_v2_force or disable custom_filter.policy_first_v2`

- overall: PASS
