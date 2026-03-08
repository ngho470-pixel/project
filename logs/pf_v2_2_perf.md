# PF-V2.2 Perf

- db: `tpch1`
- mode: `strict_mode=on`, `policy_first_v2=on`, `policy_first_v2_force=on`
- policy_file: `/tmp/z3_lab/project/logs/pf_v2_2_policy.txt`
- cases: 5

## Per Case
- P_A target=lineitem q1: status=ok correctness=PASS ours=6686.603ms rls=10873.180ms ours/rls=0.615 policy_total=408.172 project=166.616 project_row=165.407 pf2_stamp=28.950 pf2_tok_and_or=31.572 pf2_project=48.951 pf2_bins_rids=2901744 proj_sig_count=0 proj_mask_or_ops=0
- P_A target=lineitem q6: status=ok correctness=PASS ours=1355.810ms rls=5391.717ms ours/rls=0.251 policy_total=414.330 project=169.305 project_row=168.094 pf2_stamp=28.661 pf2_tok_and_or=33.071 pf2_project=49.192 pf2_bins_rids=2901744 proj_sig_count=0 proj_mask_or_ops=0
- P_B target=lineitem q1: status=ok correctness=PASS ours=10722.778ms rls=15089.376ms ours/rls=0.711 policy_total=700.972 project=394.283 project_row=393.066 pf2_stamp=19.175 pf2_tok_and_or=32.659 pf2_project=86.060 pf2_bins_rids=5712234 proj_sig_count=0 proj_mask_or_ops=0
- P_B target=lineitem q6: status=ok correctness=PASS ours=1687.142ms rls=5602.323ms ours/rls=0.301 policy_total=705.134 project=396.592 project_row=395.368 pf2_stamp=19.174 pf2_tok_and_or=33.118 pf2_project=87.287 pf2_bins_rids=5712234 proj_sig_count=0 proj_mask_or_ops=0
- P_C target=orders q3: status=ok correctness=PASS ours=482.331ms rls=873.914ms ours/rls=0.552 policy_total=68.948 project=27.856 project_row=26.667 pf2_stamp=1.386 pf2_tok_and_or=2.991 pf2_project=8.926 pf2_bins_rids=297453 proj_sig_count=0 proj_mask_or_ops=0

- median ours/rls hot-time ratio: 0.552 (<1 means ours faster)
- winning cases (ours faster, correctness PASS): 5
  - P_A q1 ours/rls=0.615
  - P_A q6 ours/rls=0.251
  - P_B q1 ours/rls=0.711
  - P_B q6 ours/rls=0.301
  - P_C q3 ours/rls=0.552
