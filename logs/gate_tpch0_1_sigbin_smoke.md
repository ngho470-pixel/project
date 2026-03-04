# SigBin Smoke (S_A q1)

## tpch0_1
- status: `ok`
- hot_ms: `2501.449`
- policy_total_ms: `2382.095`
- artifact_load_ms: `1921.963`
- term_eval_ms_total: `455.688`
- route: `class_route_single_hub=5`
- fastpath: `single_table_bin_fastpath_used=5`
- bin RID scans: `bin_rids_scanned_total=0`

## tpch1
- status: `ok`
- hot_ms: `21657.721`
- policy_total_ms: `20544.599`
- artifact_load_ms: `13861.929`
- term_eval_ms_total: `6636.649`
- route: `class_route_single_hub=5`
- fastpath: `single_table_bin_fastpath_used=5`
- bin RID scans: `bin_rids_scanned_total=0`

Both cases confirm single-table formula evaluation is signature-mask projected with zero policy-side RID list scans.
