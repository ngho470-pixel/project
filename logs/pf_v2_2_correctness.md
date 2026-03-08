# PF-V2.2 Correctness

- db: `tpch1`
- policy_file: `/tmp/z3_lab/project/logs/pf_v2_2_policy.txt`
- mode: `custom_filter.policy_first_v2=on`, `custom_filter.policy_first_v2_force=on`, `custom_filter.strict_mode=on`
- totals: PASS=5 FAIL=0 ERROR=0

## Cases
- P_A target=lineitem q1: PASS ours=(3,e766550e12c1ee6c9b875a37ab7028f0) gt=(3,e766550e12c1ee6c9b875a37ab7028f0)
- P_A target=lineitem q6: PASS ours=(1,a48343de54b0874914799f71b8d6459a) gt=(1,a48343de54b0874914799f71b8d6459a)
- P_B target=lineitem q1: PASS ours=(4,a4ae0517d01e1506b9722f8fc97f7127) gt=(4,a4ae0517d01e1506b9722f8fc97f7127)
- P_B target=lineitem q6: PASS ours=(1,42fea308b3327d5f5c58baf752fd1ed7) gt=(1,42fea308b3327d5f5c58baf752fd1ed7)
- P_C target=orders q3: PASS ours=(0,d41d8cd98f00b204e9800998ecf8427e) gt=(0,d41d8cd98f00b204e9800998ecf8427e)
