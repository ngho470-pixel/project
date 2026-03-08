# PF-V2.4 Shape Fail-Loud

- db: `tpch1`
- mode: `strict_mode=on`, `policy_first_v2=on`, `policy_first_v2_force=on`, `query_driven_mode=off`

## Cases
- F_CYCLE: PASS :: cyclic term (lineitem-part-partsupp-supplier-lineitem) :: error=`ERROR:  policy: PF-V2 path unsupported term shape on target=lineitem HINT:  disable custom_filter.policy_first_v2_force or disable custom_filter.policy_first_v2`
- F_XCMP: PASS :: cross-table comparator (unsupported in PF-V2.4) :: error=`ERROR:  policy: PF-V2 path unsupported term shape on target=lineitem HINT:  disable custom_filter.policy_first_v2_force or disable custom_filter.policy_first_v2`
- F_MHUB: PASS :: multi-hub target enforcement (unsupported in PF-V2.4) :: error=`ERROR:  policy: PF-V2 path unsupported term shape on target=lineitem HINT:  disable custom_filter.policy_first_v2_force or disable custom_filter.policy_first_v2`

- overall: PASS
