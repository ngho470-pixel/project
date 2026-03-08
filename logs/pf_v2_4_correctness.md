# PF-V2.4 Correctness

- db: `tpch1`
- policy_file: `/tmp/z3_lab/project/logs/pf_v2_4_policy.txt`
- mode: `custom_filter.policy_first_v2=on`, `custom_filter.policy_first_v2_force=on`, `custom_filter.strict_mode=on`, `custom_filter.query_driven_mode=off`
- total=12 pass=12 fail=0 error=0

## Cases
- P_A q1: PASS ours=4/aafd7ce71114558e95a2de75e99bbb5e gt=4/aafd7ce71114558e95a2de75e99bbb5e pf2(single/twohop/tree)=0/1/0 proj_sig=0 proj_mask_or=0 proj_rid=0 reason=
- P_A q6: PASS ours=1/6a7300bb9d9966aa2be6bfeda89127a7 gt=1/6a7300bb9d9966aa2be6bfeda89127a7 pf2(single/twohop/tree)=0/1/0 proj_sig=0 proj_mask_or=0 proj_rid=0 reason=
- P_B q1: PASS ours=3/95ffea12ea899ff86c4076478cbecf54 gt=3/95ffea12ea899ff86c4076478cbecf54 pf2(single/twohop/tree)=0/1/0 proj_sig=0 proj_mask_or=0 proj_rid=0 reason=
- P_B q6: PASS ours=1/6a7300bb9d9966aa2be6bfeda89127a7 gt=1/6a7300bb9d9966aa2be6bfeda89127a7 pf2(single/twohop/tree)=0/1/0 proj_sig=0 proj_mask_or=0 proj_rid=0 reason=
- P_C q3: PASS ours=389/574799e782ba5a62ad282481ef4b90ee gt=389/574799e782ba5a62ad282481ef4b90ee pf2(single/twohop/tree)=0/1/0 proj_sig=0 proj_mask_or=0 proj_rid=0 reason=
- P_C q10: PASS ours=1343/d295c798d51c42420d3a3813dfe715c1 gt=1343/d295c798d51c42420d3a3813dfe715c1 pf2(single/twohop/tree)=0/1/0 proj_sig=0 proj_mask_or=0 proj_rid=0 reason=
- P_D q5: PASS ours=0/d41d8cd98f00b204e9800998ecf8427e gt=0/d41d8cd98f00b204e9800998ecf8427e pf2(single/twohop/tree)=0/1/0 proj_sig=0 proj_mask_or=0 proj_rid=0 reason=
- P_D q8: PASS ours=2/f0591e25d45a363f1862870e41e58a12 gt=2/f0591e25d45a363f1862870e41e58a12 pf2(single/twohop/tree)=0/1/0 proj_sig=0 proj_mask_or=0 proj_rid=0 reason=
- P_E q1: PASS ours=4/efe8af7513db11ef621e445ac0fff318 gt=4/efe8af7513db11ef621e445ac0fff318 pf2(single/twohop/tree)=0/0/1 proj_sig=0 proj_mask_or=0 proj_rid=0 reason=
- P_E q6: PASS ours=1/0d0efcaf5d930800acadda9f2c0e487a gt=1/0d0efcaf5d930800acadda9f2c0e487a pf2(single/twohop/tree)=0/0/1 proj_sig=0 proj_mask_or=0 proj_rid=0 reason=
- P_F q5: PASS ours=5/9a87af99579a43ca5e7a241d426d03c5 gt=5/9a87af99579a43ca5e7a241d426d03c5 pf2(single/twohop/tree)=0/0/1 proj_sig=0 proj_mask_or=0 proj_rid=0 reason=
- P_F q8: PASS ours=2/40750f34bb9af5af9e2d8201d1101ed5 gt=2/40750f34bb9af5af9e2d8201d1101ed5 pf2(single/twohop/tree)=0/0/1 proj_sig=0 proj_mask_or=0 proj_rid=0 reason=
