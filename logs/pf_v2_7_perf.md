# PF-V2.7 Perf

- db: `tpch1`
- policy_file: `/tmp/z3_lab/project/logs/pf_v2_7_policy.txt`
- mode: `strict_mode=on`, `query_driven_mode=off`, `policy_first_v2=on`, `policy_first_v2_force=on`
- cases: 6

## Per Case
- P29 target=lineitem q1: status=ok correctness=PASS ours=12047.990ms rls=23794.562ms ours/rls=0.506 policy_total=1870.507 project=1446.828 pf2_cmp=1/1 cmp_build_ms=186.061 key2(entries/build/lookups)=800000/186.061/6001215 cmp_checks/rejects=6001215/14823 pf2_project=1063.803 pf2_total=1356.096 proj_sig=0 proj_mask_or=0 proj_rid=0
- P29 target=lineitem q6: status=ok correctness=PASS ours=2681.253ms rls=11747.274ms ours/rls=0.228 policy_total=1847.082 project=1424.338 pf2_cmp=1/1 cmp_build_ms=185.065 key2(entries/build/lookups)=800000/185.065/6001215 cmp_checks/rejects=6001215/14823 pf2_project=1049.720 pf2_total=1334.966 proj_sig=0 proj_mask_or=0 proj_rid=0
- P29 target=lineitem q9: status=ok correctness=PASS ours=8163.026ms rls=5414.341ms ours/rls=1.508 policy_total=1868.680 project=1441.762 pf2_cmp=1/1 cmp_build_ms=186.891 key2(entries/build/lookups)=800000/186.891/6001215 cmp_checks/rejects=6001215/14823 pf2_project=1064.223 pf2_total=1351.303 proj_sig=0 proj_mask_or=0 proj_rid=0
- P29F target=lineitem q6: status=ok correctness=PASS ours=2500.448ms rls=12982.521ms ours/rls=0.193 policy_total=1645.322 project=1192.100 pf2_cmp=1/1 cmp_build_ms=92.686 key2(entries/build/lookups)=400310/92.686/5623381 cmp_checks/rejects=5623381/2629822 pf2_project=973.990 pf2_total=1137.554 proj_sig=0 proj_mask_or=0 proj_rid=0
- P29T target=lineitem q1: status=ok correctness=PASS ours=8584.396ms rls=14427.649ms ours/rls=0.595 policy_total=1837.090 project=1309.672 pf2_cmp=1/1 cmp_build_ms=183.012 key2(entries/build/lookups)=800000/183.012/3274126 cmp_checks/rejects=3274126/8123 pf2_project=940.780 pf2_total=1220.800 proj_sig=0 proj_mask_or=0 proj_rid=0
- P29G target=lineitem q6: status=ok correctness=PASS ours=1536.652ms rls=12831.440ms ours/rls=0.120 policy_total=1494.382 project=1072.468 pf2_cmp=1/1 cmp_build_ms=186.689 key2(entries/build/lookups)=800000/186.689/6001215 cmp_checks/rejects=6001215/5985809 pf2_project=697.141 pf2_total=983.137 proj_sig=0 proj_mask_or=0 proj_rid=0

- median ours/rls hot-time ratio: 0.367 (target <= 0.7)

- query_driven_mode asserted OFF in script env
