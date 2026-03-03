# Class Engine Witness-Witness Comparator Perf

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 4
- median ours/rls hot-time ratio: 0.193 (target <= 0.85)

## Cases
- W1 target=lineitem q6: status=ok correctness=PASS ours=2169.569ms rls=11023.825ms ours/rls=0.197 ww(total/supported/filter_check/filter_reject)=1/1/3150000/74500 proj_sig/mask/rid=0/0/0 err=
- W2 target=lineitem q6: status=ok correctness=PASS ours=2078.947ms rls=10994.134ms ours/rls=0.189 ww(total/supported/filter_check/filter_reject)=1/1/3150000/50004 proj_sig/mask/rid=0/0/0 err=
- W3 target=lineitem q6: status=ok correctness=PASS ours=1808.088ms rls=10904.042ms ours/rls=0.166 ww(total/supported/filter_check/filter_reject)=1/1/1827205/1212423 proj_sig/mask/rid=0/0/0 err=
- W1 target=lineitem q1: status=ok correctness=PASS ours=11505.887ms rls=22951.448ms ours/rls=0.501 ww(total/supported/filter_check/filter_reject)=1/1/3150000/74500 proj_sig/mask/rid=0/0/0 err=
