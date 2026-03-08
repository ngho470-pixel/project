# Gate tpch0_1 stage0 (partial)

- csv: `logs/gate_tpch0_1_stage0.csv`
- rows_recorded: 82
- ok: 80
- errors: 2
- mismatches_vs_rls_index: 0
- median ours/rls_index ratio (recorded rows): 16.710

## Notable
- S_A q1 ours scan_mode=TID reason=sparse_tid allow_density=0.067008 rows_seen=40243 rows_pass=40243
- error case: baseline=view_based set=S_D q1 type=timeout msg=ERROR:  canceling statement due to statement timeout
- error case: baseline=view_based set=S_D q3 type=timeout msg=ERROR:  canceling statement due to statement timeout
