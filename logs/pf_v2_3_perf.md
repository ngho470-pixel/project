# PF-V2.3 Perf

- db: `tpch1`
- policy_file: `/tmp/z3_lab/project/logs/pf_v2_3_policy.txt`
- mode: `strict_mode=on`, `query_driven_mode=off`, `policy_first_v2=on`, `policy_first_v2_force=on`
- cases: 6

## Per Case
- P_A target=lineitem q1: status=ok correctness=PASS ours=4308.299ms rls=15903.794ms ours/rls=0.271 policy_total=317.942 project=104.564 project_row=103.401 pf2_two_hop=1 pf2_stampA/B=18.226/1.642 pf2_tok_compose=23.140 pf2_project=23.603 pf2_rowsA/B=1500000/150000 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_A target=lineitem q6: status=ok correctness=PASS ours=1175.239ms rls=10692.555ms ours/rls=0.110 policy_total=330.785 project=106.901 project_row=105.723 pf2_two_hop=1 pf2_stampA/B=16.635/1.655 pf2_tok_compose=21.554 pf2_project=23.683 pf2_rowsA/B=1500000/150000 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_B target=lineitem q1: status=ok correctness=PASS ours=3554.928ms rls=1928.155ms ours/rls=1.844 policy_total=372.614 project=98.857 project_row=97.684 pf2_two_hop=1 pf2_stampA/B=19.603/1.662 pf2_tok_compose=24.528 pf2_project=14.460 pf2_rowsA/B=1500000/150000 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_B target=lineitem q6: status=ok correctness=PASS ours=1235.476ms rls=7228.873ms ours/rls=0.171 policy_total=364.348 project=97.413 project_row=96.182 pf2_two_hop=1 pf2_stampA/B=19.603/1.671 pf2_tok_compose=24.542 pf2_project=14.381 pf2_rowsA/B=1500000/150000 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_C target=orders q3: status=ok correctness=PASS ours=1596.897ms rls=1747.923ms ours/rls=0.914 policy_total=83.280 project=33.001 project_row=31.801 pf2_two_hop=1 pf2_stampA/B=1.115/0.001 pf2_tok_compose=1.340 pf2_project=2.768 pf2_rowsA/B=150000/25 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_C target=orders q10: status=ok correctness=PASS ours=1054.919ms rls=1416.368ms ours/rls=0.745 policy_total=81.199 project=32.898 project_row=31.739 pf2_two_hop=1 pf2_stampA/B=1.111/0.001 pf2_tok_compose=1.333 pf2_project=2.885 pf2_rowsA/B=150000/25 proj_sig=0 proj_mask_or=0 proj_rid=0

- median ours/rls hot-time ratio: 0.508 (target <= 0.8)
