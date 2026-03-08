# PF-V2.3 Shape Fail-Loud

- db: `tpch1`
- mode: `strict_mode=on`, `policy_first_v2=on`, `policy_first_v2_force=on`

## Cases
- F_3HOP: PASS :: 3-hop chain (lineitem->orders->customer->nation) :: error=`ERROR:  policy: PF-V2 path unsupported term shape on target=lineitem HINT:  disable custom_filter.policy_first_v2_force or disable custom_filter.policy_first_v2`
- F_MHUB: PASS :: multi-hub term (orderkey + suppkey joins from target) :: error=`ERROR:  policy: PF-V2 path unsupported term shape on target=lineitem HINT:  disable custom_filter.policy_first_v2_force or disable custom_filter.policy_first_v2`
- F_XCMP: PASS :: cross-table comparator (unsupported in PF2) :: error=`ERROR:  policy: PF-V2 path unsupported term shape on target=lineitem HINT:  disable custom_filter.policy_first_v2_force or disable custom_filter.policy_first_v2`

- overall: PASS
