# tpch0_1 SigBin Smoke

- case: `db=tpch0_1`, `baseline=ours`, `policy_set=S_A (1..5)`, `query=q1`
- status: `ok`
- hot_ms: `2501.449`
- policy_profile_query: `policy_total_ms=2382.095`, `artifact_load_ms=1921.963`, `term_eval_ms_total=455.688`
- route: `single_hub` only (`class_route_single_hub=5`)
- single-table signature fastpath: `single_table_bin_fastpath_used=5`
- RID scan counters on policy side: `bin_rids_scanned_total=0`

This confirms the single-table formula path is now signature-mask projected (no bin RID list scans) for this case.
