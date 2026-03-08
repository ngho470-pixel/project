# PF-V2.5 Perf

- db: `tpch1`
- policy_file: `/tmp/z3_lab/project/logs/pf_v2_5_policy.txt`
- mode: `strict_mode=on`, `query_driven_mode=off`, `policy_first_v2=on`, `policy_first_v2_force=on`
- cases: 6

## Per Case
- P27 target=lineitem q1: status=ok correctness=PASS ours=11476.049ms rls=15601.963ms ours/rls=0.736 policy_total=1273.884 project=799.983 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=96.414 cmp_checks/rejects=6001215/137517 tree_edges=2 tree_rows=9001215 tree_update_ms=282.754 proj_sig=0 proj_mask_or=0 proj_rid=0
- P27 target=lineitem q6: status=ok correctness=PASS ours=2289.865ms rls=5933.835ms ours/rls=0.386 policy_total=1280.493 project=799.975 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=96.829 cmp_checks/rejects=6001215/137517 tree_edges=2 tree_rows=9001215 tree_update_ms=282.198 proj_sig=0 proj_mask_or=0 proj_rid=0
- P27F target=lineitem q6: status=ok correctness=PASS ours=2109.148ms rls=6174.768ms ours/rls=0.342 policy_total=1137.394 project=672.391 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=102.327 cmp_checks/rejects=2901744/68633 tree_edges=2 tree_rows=9001215 tree_update_ms=301.615 proj_sig=0 proj_mask_or=0 proj_rid=0
- P26 target=orders q10: status=ok correctness=PASS ours=1808.361ms rls=3434.113ms ours/rls=0.527 policy_total=351.208 project=226.551 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=6.051 cmp_checks/rejects=1500000/12248 tree_edges=2 tree_rows=1749996 tree_update_ms=76.417 proj_sig=0 proj_mask_or=0 proj_rid=0
- P28 target=partsupp q11: status=ok correctness=PASS ours=1190.155ms rls=2368.157ms ours/rls=0.503 policy_total=126.586 project=83.473 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=11.994 cmp_checks/rejects=800000/679 tree_edges=2 tree_rows=1200000 tree_update_ms=39.421 proj_sig=0 proj_mask_or=0 proj_rid=0
- P30 target=supplier q5: status=ok correctness=PASS ours=934.191ms rls=1476.149ms ours/rls=0.633 policy_total=23.810 project=9.997 pf2_tree=1 pf2_cmp=1/1 cmp_build_ms=3.213 cmp_checks/rejects=10000/1 tree_edges=2 tree_rows=310000 tree_update_ms=3.434 proj_sig=0 proj_mask_or=0 proj_rid=0

- median ours/rls hot-time ratio: 0.515 (target <= 0.7)
