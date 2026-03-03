# Class Engine Witness-Witness Chain Comparator Correctness

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 5
- pass/fail/error: 5/0/0

## Cases
- C1 target=partsupp qps: status=PASS ours=(1,4f1b5af823b716dd3ecaa55da7b67e01) gt=(1,4f1b5af823b716dd3ecaa55da7b67e01) chain(total/supported/steps/build_ms/check/reject)=1/1/4/169.694/12468/12347 proj_sig/mask/rid=0/0/0 err=
- C2 target=partsupp qps: status=PASS ours=(1,5ff0527e53908145d9a41589c2491950) gt=(1,5ff0527e53908145d9a41589c2491950) chain(total/supported/steps/build_ms/check/reject)=1/1/4/161.580/12468/12293 proj_sig/mask/rid=0/0/0 err=
- C0 target=partsupp qps: status=PASS ours=(1,5ff0527e53908145d9a41589c2491950) gt=(1,5ff0527e53908145d9a41589c2491950) chain(total/supported/steps/build_ms/check/reject)=0/0/0/0.000/0/0 proj_sig/mask/rid=0/0/0 err=
- F1 target=partsupp qps: status=PASS ours=(,) gt=(,) chain(total/supported/steps/build_ms/check/reject)=///// proj_sig/mask/rid=// err=
- CHAIN_EFFECT target=partsupp qps: status=PASS ours=(1,4f1b5af823b716dd3ecaa55da7b67e01) gt=(1,5ff0527e53908145d9a41589c2491950) chain(total/supported/steps/build_ms/check/reject)=///// proj_sig/mask/rid=// err=
