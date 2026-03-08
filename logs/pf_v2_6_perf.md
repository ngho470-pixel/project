# PF-V2.6 Perf

- db: `tpch1`
- policy_file: `/tmp/z3_lab/project/logs/pf_v2_6_policy.txt`
- mode: `strict_mode=on`, `query_driven_mode=off`, `policy_first_v2=on`, `policy_first_v2_force=on`
- cases: 7

## Per Case
- P62 target=lineitem q1: status=ok correctness=PASS ours=12440.996ms rls=29761.227ms ours/rls=0.418 policy_total=2104.363 project=1788.663 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=225.768 key2(entries/build/lookups)=800000/225.768/6001215 cmp_checks/rejects=6001215/0 tree_edges=4 tree_rows=8421215 tree_update_ms=340.835 proj_sig=0 proj_mask_or=0 proj_rid=0
- P62 target=lineitem q6: status=ok correctness=PASS ours=3012.624ms rls=16114.687ms ours/rls=0.187 policy_total=2129.915 project=1813.181 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=224.497 key2(entries/build/lookups)=800000/224.497/6001215 cmp_checks/rejects=6001215/0 tree_edges=4 tree_rows=8421215 tree_update_ms=338.563 proj_sig=0 proj_mask_or=0 proj_rid=0
- P27 target=lineitem q1: status=ok correctness=PASS ours=11565.650ms rls=15571.295ms ours/rls=0.743 policy_total=1244.272 project=769.045 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=95.339 key2(entries/build/lookups)=0/0.000/0 cmp_checks/rejects=6001215/137517 tree_edges=2 tree_rows=9001215 tree_update_ms=275.685 proj_sig=0 proj_mask_or=0 proj_rid=0
- P27 target=lineitem q6: status=ok correctness=PASS ours=2259.491ms rls=5903.310ms ours/rls=0.383 policy_total=1241.232 project=767.060 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=94.803 key2(entries/build/lookups)=0/0.000/0 cmp_checks/rejects=6001215/137517 tree_edges=2 tree_rows=9001215 tree_update_ms=276.316 proj_sig=0 proj_mask_or=0 proj_rid=0
- P26 target=orders q10: status=ok correctness=PASS ours=1817.392ms rls=3443.785ms ours/rls=0.528 policy_total=348.343 project=223.869 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=6.038 key2(entries/build/lookups)=0/0.000/0 cmp_checks/rejects=1500000/12248 tree_edges=2 tree_rows=1749996 tree_update_ms=75.223 proj_sig=0 proj_mask_or=0 proj_rid=0
- P28 target=partsupp q11: status=ok correctness=PASS ours=1188.336ms rls=2369.148ms ours/rls=0.502 policy_total=124.459 project=80.905 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=11.851 key2(entries/build/lookups)=0/0.000/0 cmp_checks/rejects=800000/679 tree_edges=2 tree_rows=1200000 tree_update_ms=38.603 proj_sig=0 proj_mask_or=0 proj_rid=0
- P30 target=supplier q5: status=ok correctness=PASS ours=934.546ms rls=1476.270ms ours/rls=0.633 policy_total=23.186 project=9.100 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=2.936 key2(entries/build/lookups)=0/0.000/0 cmp_checks/rejects=10000/1 tree_edges=2 tree_rows=310000 tree_update_ms=3.047 proj_sig=0 proj_mask_or=0 proj_rid=0

- median ours/rls hot-time ratio: 0.502 (target <= 0.7)
