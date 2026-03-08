# PF-V2.7 Shape Fail-Loud

- db: `tpch1`
- mode: `strict_mode=on`, `query_driven_mode=off`, `policy_first_v2=on`, `policy_first_v2_force=on`

## Cases
- F_XNE: PASS :: cross-table != unsupported in PF-V2.7 cycle path :: error=`ERROR:  policy: PF-V2 path unsupported term shape on target=lineitem HINT:  disable custom_filter.policy_first_v2_force or disable custom_filter.policy_first_v2`
- F_CYCLE_EXTRA: PASS :: cycle with extra table unsupported in PF-V2.7 cycle-rectangle subset :: error=`ERROR:  policy: PF-V2 path unsupported term shape on target=lineitem HINT:  disable custom_filter.policy_first_v2_force or disable custom_filter.policy_first_v2`
- F_KGT2: PASS :: comparator separator arity >2 unsupported under PF force :: error=`ERROR:  policy: PF-V2 path unsupported term shape on target=supplier HINT:  disable custom_filter.policy_first_v2_force or disable custom_filter.policy_first_v2`

- query_driven_mode asserted OFF in script env
- overall: PASS
