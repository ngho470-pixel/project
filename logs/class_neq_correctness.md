# Class Engine `!=` Correctness

- db: `tpch1`
- mode: `strict_mode=on`
- cases: 7
- pass/fail/error: 7/0/0

## Cases
- N1 target=lineitem q6: status=PASS ours=(1,a576fdadec80e7dfb58a895ec50285c3) gt=(1,a576fdadec80e7dfb58a895ec50285c3) cmp=0/0 key_arity_max=0 proj_sig/mask/rid=0/0/0 err=
- N2 target=lineitem q6: status=PASS ours=(1,743dab9f0f0ef5f943373b85dbad83a9) gt=(1,743dab9f0f0ef5f943373b85dbad83a9) cmp=0/0 key_arity_max=0 proj_sig/mask/rid=0/0/0 err=
- N3 target=orders q3: status=PASS ours=(0,d41d8cd98f00b204e9800998ecf8427e) gt=(0,d41d8cd98f00b204e9800998ecf8427e) cmp=1/0 key_arity_max=1 proj_sig/mask/rid=0/0/0 err=
- N4 target=orders q3: status=PASS ours=(11438,0638c8fc47b7e22664195bd8cd91b823) gt=(11438,0638c8fc47b7e22664195bd8cd91b823) cmp=1/1 key_arity_max=1 proj_sig/mask/rid=0/0/0 err=
- N4 target=orders q10: status=PASS ours=(37690,91ea978b16d201b9ee7f85e96bf9c318) gt=(37690,91ea978b16d201b9ee7f85e96bf9c318) cmp=1/1 key_arity_max=1 proj_sig/mask/rid=0/0/0 err=
- N5 target=lineitem q6: status=PASS ours=(1,c639ef879f0efccdab0ceae428d1c1cf) gt=(1,c639ef879f0efccdab0ceae428d1c1cf) cmp=1/1 key_arity_max=2 proj_sig/mask/rid=0/0/0 err=
- N5 target=lineitem q9: status=PASS ours=(175,81cc75a18bd8289309ec6f0fb7bec64c) gt=(175,81cc75a18bd8289309ec6f0fb7bec64c) cmp=/ key_arity_max= proj_sig/mask/rid=// err=
