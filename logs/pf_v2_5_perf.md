# PF-V2.5 Perf

- db: `tpch1`
- policy_file: `/tmp/z3_lab/project/logs/pf_v2_5_policy.txt`
- mode: `strict_mode=on`, `query_driven_mode=off`, `policy_first_v2=on`, `policy_first_v2_force=on`
- cases: 6

## Per Case
- P27 target=lineitem q1: status=ok correctness=PASS ours=11505.838ms rls=15601.938ms ours/rls=0.737 policy_total=1257.175 project=772.656 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=94.407 cmp_checks/rejects=6001215/137517 tree_edges=2 tree_rows=9001215 tree_update_ms=279.000 proj_sig=0 proj_mask_or=0 proj_rid=0
- P27 target=lineitem q6: status=ok correctness=PASS ours=2289.565ms rls=5903.427ms ours/rls=0.388 policy_total=1262.172 project=776.629 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=94.724 cmp_checks/rejects=6001215/137517 tree_edges=2 tree_rows=9001215 tree_update_ms=278.017 proj_sig=0 proj_mask_or=0 proj_rid=0
- P27F target=lineitem q6: status=ok correctness=PASS ours=2108.992ms rls=6204.625ms ours/rls=0.340 policy_total=1120.820 project=653.923 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=102.602 cmp_checks/rejects=2901744/68633 tree_edges=2 tree_rows=9001215 tree_update_ms=298.216 proj_sig=0 proj_mask_or=0 proj_rid=0
- P26 target=orders q10: status=ok correctness=PASS ours=1796.464ms rls=3425.496ms ours/rls=0.524 policy_total=337.089 project=210.681 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=6.020 cmp_checks/rejects=1500000/12248 tree_edges=2 tree_rows=1749996 tree_update_ms=76.579 proj_sig=0 proj_mask_or=0 proj_rid=0
- P28 target=partsupp q11: status=ok correctness=PASS ours=1145.067ms rls=2368.817ms ours/rls=0.483 policy_total=122.819 project=79.087 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=11.864 cmp_checks/rejects=800000/679 tree_edges=2 tree_rows=1200000 tree_update_ms=38.856 proj_sig=0 proj_mask_or=0 proj_rid=0
- P30 target=supplier q5: status=ok correctness=PASS ours=934.199ms rls=1476.187ms ours/rls=0.633 policy_total=23.198 project=9.201 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=2.932 cmp_checks/rejects=10000/1 tree_edges=2 tree_rows=310000 tree_update_ms=3.126 proj_sig=0 proj_mask_or=0 proj_rid=0

- median ours/rls hot-time ratio: 0.504 (target <= 0.7)
