# Class Engine Witness-Witness Comparator Correctness

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 5
- pass/fail/error: 5/0/0

## Cases
- W1 target=lineitem q1: status=PASS ours=(4,f2f6bcf60647a8bedda7566daa0bda8b) gt=(4,f2f6bcf60647a8bedda7566daa0bda8b) route(tree/cycle)=1/0 ww(total/supported/filter_check/filter_reject)=1/1/3150000/74500 proj_sig/mask/rid=0/0/0 err=
- W1 target=lineitem q6: status=PASS ours=(1,a37d0941996b393b8a482a4f371ae769) gt=(1,a37d0941996b393b8a482a4f371ae769) route(tree/cycle)=1/0 ww(total/supported/filter_check/filter_reject)=1/1/3150000/74500 proj_sig/mask/rid=0/0/0 err=
- W2 target=lineitem q1: status=PASS ours=(4,a2b9213f118bea73614f99abc44624fe) gt=(4,a2b9213f118bea73614f99abc44624fe) route(tree/cycle)=1/0 ww(total/supported/filter_check/filter_reject)=1/1/3150000/50004 proj_sig/mask/rid=0/0/0 err=
- W2 target=lineitem q6: status=PASS ours=(1,a48343de54b0874914799f71b8d6459a) gt=(1,a48343de54b0874914799f71b8d6459a) route(tree/cycle)=1/0 ww(total/supported/filter_check/filter_reject)=1/1/3150000/50004 proj_sig/mask/rid=0/0/0 err=
- W3 target=lineitem q6: status=PASS ours=(1,6a7300bb9d9966aa2be6bfeda89127a7) gt=(1,6a7300bb9d9966aa2be6bfeda89127a7) route(tree/cycle)=1/0 ww(total/supported/filter_check/filter_reject)=1/1/1827205/1212423 proj_sig/mask/rid=0/0/0 err=
