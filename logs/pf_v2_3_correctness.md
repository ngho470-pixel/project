# PF-V2.3 Correctness

- db: `tpch1`
- policy_file: `/tmp/z3_lab/project/logs/pf_v2_3_policy.txt`
- mode: `custom_filter.policy_first_v2=on`, `custom_filter.policy_first_v2_force=on`, `custom_filter.strict_mode=on`
- totals: PASS=8 FAIL=0 ERROR=0

## Cases
- P_A target=lineitem q1: PASS ours=(4,aafd7ce71114558e95a2de75e99bbb5e) gt=(4,aafd7ce71114558e95a2de75e99bbb5e) pf2_two_hop=1 pf2_supported=1 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_A target=lineitem q6: PASS ours=(1,6a7300bb9d9966aa2be6bfeda89127a7) gt=(1,6a7300bb9d9966aa2be6bfeda89127a7) pf2_two_hop=1 pf2_supported=1 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_B target=lineitem q1: PASS ours=(3,95ffea12ea899ff86c4076478cbecf54) gt=(3,95ffea12ea899ff86c4076478cbecf54) pf2_two_hop=1 pf2_supported=1 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_B target=lineitem q6: PASS ours=(1,6a7300bb9d9966aa2be6bfeda89127a7) gt=(1,6a7300bb9d9966aa2be6bfeda89127a7) pf2_two_hop=1 pf2_supported=1 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_C target=orders q3: PASS ours=(389,574799e782ba5a62ad282481ef4b90ee) gt=(389,574799e782ba5a62ad282481ef4b90ee) pf2_two_hop=1 pf2_supported=1 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_C target=orders q10: PASS ours=(1343,d295c798d51c42420d3a3813dfe715c1) gt=(1343,d295c798d51c42420d3a3813dfe715c1) pf2_two_hop=1 pf2_supported=1 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_D target=supplier q5: PASS ours=(0,d41d8cd98f00b204e9800998ecf8427e) gt=(0,d41d8cd98f00b204e9800998ecf8427e) pf2_two_hop=1 pf2_supported=1 proj_sig=0 proj_mask_or=0 proj_rid=0
- P_D target=supplier q8: PASS ours=(2,f0591e25d45a363f1862870e41e58a12) gt=(2,f0591e25d45a363f1862870e41e58a12) pf2_two_hop=1 pf2_supported=1 proj_sig=0 proj_mask_or=0 proj_rid=0
