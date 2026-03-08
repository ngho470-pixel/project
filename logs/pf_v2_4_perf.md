# PF-V2.4 Perf

- db: `tpch1`
- policy_file: `/tmp/z3_lab/project/logs/pf_v2_4_policy.txt`
- mode: `strict_mode=on`, `query_driven_mode=off`, `policy_first_v2=on`, `policy_first_v2_force=on`
- cases: 6

## Per Case
- P_A target=lineitem q1: status=ok correctness=PASS ours=4337.678ms rls=15963.432ms ours/rls=0.272 policy_total=321.347 project=104.202 pf2_tree=0 tree_edges=0 tree_rows=0 tree_update_ms=0.000 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_A target=lineitem q6: status=ok correctness=PASS ours=1205.306ms rls=10662.919ms ours/rls=0.113 policy_total=331.042 project=106.108 pf2_tree=0 tree_edges=0 tree_rows=0 tree_update_ms=0.000 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_C target=orders q10: status=ok correctness=PASS ours=1054.729ms rls=1415.912ms ours/rls=0.745 policy_total=82.595 project=33.374 pf2_tree=0 tree_edges=0 tree_rows=0 tree_update_ms=0.000 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_D target=supplier q5: status=ok correctness=PASS ours=904.004ms rls=903.869ms ours/rls=1.000 policy_total=2.844 project=2.021 pf2_tree=0 tree_edges=0 tree_rows=0 tree_update_ms=0.000 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_E target=lineitem q6: status=ok correctness=PASS ours=1474.569ms rls=13726.282ms ours/rls=0.107 policy_total=646.787 project=392.404 pf2_tree=1 tree_edges=6 tree_rows=7666868 tree_update_ms=318.703 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_F target=region q5: status=ok correctness=PASS ours=934.236ms rls=903.883ms ours/rls=1.034 policy_total=14.335 project=7.258 pf2_tree=1 tree_edges=5 tree_rows=160055 tree_update_ms=3.059 proj_sig=0 proj_mask_or=0 proj_rid=0

- median ours/rls hot-time ratio: 0.508 (target <= 0.7)
