# PFV3.0b-2 Correctness

- db: `tpch1`
- mode: `strict_mode=on`, `query_driven_mode=off`, `pfv3=on`, `pfv3_force=on`, `pfv3_allow_fallback=off`
- note: previous pre-fix `logs/pfv3_0b2_correctness.*` outputs are STALE (PFV3 join-var + TD pruning fixes landed after those runs)
- cases: 4
- result: PASS=4 FAIL=0 ERROR=0

## Cases
- P0S target=lineitem q1: PASS ours=4/16a2c377e195c71ab2da21ed2cdd2759 gt=4/16a2c377e195c71ab2da21ed2cdd2759 route=pfv3_solver gate=PFV3_OK_EQ_UNARY td_bags/width=1/0 factor_tuples=1 msg_tuples=0 target_rows=468252 stamp_ms=95.677 proj_sig/mask/rid=0/0/0 reason=
- P0J target=lineitem q3: PASS ours=9824/051562321db985a8551c3e9f73fdb1c7 gt=9824/051562321db985a8551c3e9f73fdb1c7 route=pfv3_solver gate=PFV3_OK_EQ_UNARY td_bags/width=1/0 factor_tuples=2229413 msg_tuples=729413 target_rows=0 stamp_ms=200.284 proj_sig/mask/rid=0/0/0 reason=
- P0C target=lineitem q3: PASS ours=0/d41d8cd98f00b204e9800998ecf8427e gt=0/d41d8cd98f00b204e9800998ecf8427e route=pfv3_solver gate=PFV3_OK_EQ_UNARY td_bags/width=2/1 factor_tuples=3029752 msg_tuples=297453 target_rows=0 stamp_ms=85.492 proj_sig/mask/rid=0/0/0 reason=
- P0R target=lineitem q1: PASS ours=4/a513d93918003b6a1f7839f53b965f4f gt=4/a513d93918003b6a1f7839f53b965f4f route=pfv3_solver gate=PFV3_OK_EQ_UNARY td_bags/width=2/1 factor_tuples=1199851 msg_tuples=400086 target_rows=0 stamp_ms=797.501 proj_sig/mask/rid=0/0/0 reason=
