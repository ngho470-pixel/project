# PF-V2.6 Correctness

- db: `tpch1`
- mode: `strict_mode=on`, `query_driven_mode=off`, `policy_first_v2=on`, `policy_first_v2_force=on`
- cases: 10
- result: PASS=10 FAIL=0 ERROR=0

## Cases
- P62 target=lineitem q1: PASS rows/hash ours=4/a2b9213f118bea73614f99abc44624fe gt=4/a2b9213f118bea73614f99abc44624fe cmp_total/supported=1/1 cmp_key_arity_max=2 key2(entries/build/lookups)=800000/222.112/6001215 proj_sig/mask/rid=0/0/0 reason=
- P62 target=lineitem q6: PASS rows/hash ours=1/a48343de54b0874914799f71b8d6459a gt=1/a48343de54b0874914799f71b8d6459a cmp_total/supported=1/1 cmp_key_arity_max=2 key2(entries/build/lookups)=800000/222.339/6001215 proj_sig/mask/rid=0/0/0 reason=
- P26 target=orders q3: PASS rows/hash ours=11380/15931cd636470a49639ce0e11029f517 gt=11380/15931cd636470a49639ce0e11029f517 cmp_total/supported=1/1 cmp_key_arity_max=1 key2(entries/build/lookups)=0/0.000/0 proj_sig/mask/rid=0/0/0 reason=
- P26 target=orders q10: PASS rows/hash ours=37548/9fcbeaa2a2896d0927df1a4432bec979 gt=37548/9fcbeaa2a2896d0927df1a4432bec979 cmp_total/supported=1/1 cmp_key_arity_max=1 key2(entries/build/lookups)=0/0.000/0 proj_sig/mask/rid=0/0/0 reason=
- P27 target=lineitem q1: PASS rows/hash ours=4/c4fa20fc9ae293fda25f1d3f134991af gt=4/c4fa20fc9ae293fda25f1d3f134991af cmp_total/supported=1/1 cmp_key_arity_max=1 key2(entries/build/lookups)=0/0.000/0 proj_sig/mask/rid=0/0/0 reason=
- P27 target=lineitem q6: PASS rows/hash ours=1/134df7d7782bd6a4d75ffc37613862a8 gt=1/134df7d7782bd6a4d75ffc37613862a8 cmp_total/supported=1/1 cmp_key_arity_max=1 key2(entries/build/lookups)=0/0.000/0 proj_sig/mask/rid=0/0/0 reason=
- P28 target=partsupp q9: PASS rows/hash ours=175/4952fb447337565af5db7f9d0cc4482d gt=175/4952fb447337565af5db7f9d0cc4482d cmp_total/supported=1/1 cmp_key_arity_max=1 key2(entries/build/lookups)=0/0.000/0 proj_sig/mask/rid=0/0/0 reason=
- P28 target=partsupp q11: PASS rows/hash ours=22542/b32abf1d842b38619dc4099794e6a5c7 gt=22542/b32abf1d842b38619dc4099794e6a5c7 cmp_total/supported=1/1 cmp_key_arity_max=1 key2(entries/build/lookups)=0/0.000/0 proj_sig/mask/rid=0/0/0 reason=
- P30 target=supplier q5: PASS rows/hash ours=5/9a87af99579a43ca5e7a241d426d03c5 gt=5/9a87af99579a43ca5e7a241d426d03c5 cmp_total/supported=1/1 cmp_key_arity_max=1 key2(entries/build/lookups)=0/0.000/0 proj_sig/mask/rid=0/0/0 reason=
- P27F target=lineitem q6: PASS rows/hash ours=1/134df7d7782bd6a4d75ffc37613862a8 gt=1/134df7d7782bd6a4d75ffc37613862a8 cmp_total/supported=1/1 cmp_key_arity_max=1 key2(entries/build/lookups)=0/0.000/0 proj_sig/mask/rid=0/0/0 reason=
