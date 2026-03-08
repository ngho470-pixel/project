# tpch0_1 Case A Profile (S_A, baseline=ours)

- db: `tpch0_1`
- policy_ids: `1,2,3,4,5`
- setup_ms: `2942.928`
- strict_mode: `on` (ours baseline session setup)

## Per Query
- q1: status=ok ms=2380.964 rss_kb=151324 sat_ms=0.000 sat_models_total=0 sat_conflicts=0 sat_decisions=0 terms_total=5 term_eval_ms_total=98.305 combine_algebra_ms=0.854 allow_rows_total=40243 route_terms={"single_hub": 5} bin_ops_total=261761 bins_touched_total=261736 bin_rids_scanned_total=7460747 heap_rows_scanned_total=0 allow_cache_hit=0 allow_cache_miss=1 allow_cache_build_ms=101.925 inv_proj_sig=0 inv_proj_mask=0 inv_proj_rid=0 error_type= error_msg=
- q3: status=ok ms=2139.171 rss_kb=158756 sat_ms=0.000 sat_models_total=0 sat_conflicts=0 sat_decisions=0 terms_total=0 term_eval_ms_total=0.000 combine_algebra_ms=0.000 allow_rows_total=40243 route_terms={} bin_ops_total=0 bins_touched_total=0 bin_rids_scanned_total=0 heap_rows_scanned_total=0 allow_cache_hit=1 allow_cache_miss=0 allow_cache_build_ms=0.000 inv_proj_sig=0 inv_proj_mask=0 inv_proj_rid=0 error_type= error_msg=
- q6: status=ok ms=2048.678 rss_kb=159268 sat_ms=0.000 sat_models_total=0 sat_conflicts=0 sat_decisions=0 terms_total=0 term_eval_ms_total=0.000 combine_algebra_ms=0.000 allow_rows_total=40243 route_terms={} bin_ops_total=0 bins_touched_total=0 bin_rids_scanned_total=0 heap_rows_scanned_total=0 allow_cache_hit=1 allow_cache_miss=0 allow_cache_build_ms=0.000 inv_proj_sig=0 inv_proj_mask=0 inv_proj_rid=0 error_type= error_msg=
- q10: status=ok ms=2108.813 rss_kb=159780 sat_ms=0.000 sat_models_total=0 sat_conflicts=0 sat_decisions=0 terms_total=0 term_eval_ms_total=0.000 combine_algebra_ms=0.000 allow_rows_total=40243 route_terms={} bin_ops_total=0 bins_touched_total=0 bin_rids_scanned_total=0 heap_rows_scanned_total=0 allow_cache_hit=1 allow_cache_miss=0 allow_cache_build_ms=0.000 inv_proj_sig=0 inv_proj_mask=0 inv_proj_rid=0 error_type= error_msg=
- q11: status=ok ms=32.201 rss_kb=159780 sat_ms=0 sat_models_total=0 sat_conflicts=0 sat_decisions=0 terms_total=0 term_eval_ms_total=0 combine_algebra_ms=0 allow_rows_total=0 route_terms={} bin_ops_total=0 bins_touched_total=0 bin_rids_scanned_total=0 heap_rows_scanned_total=0 allow_cache_hit=0 allow_cache_miss=0 allow_cache_build_ms=0 inv_proj_sig=0 inv_proj_mask=0 inv_proj_rid=0 error_type= error_msg=

## Raw Route Lines
- q1:
  - NOTICE:  class_route_term: target=lineitem route=single_hub width=-1 bags=-1 term_atoms=13,7 reason=single_table_formula_bin_fast
  - NOTICE:  class_route_term: target=lineitem route=single_hub width=-1 bags=-1 term_atoms=4,1,10,5,3,8 reason=single_table_formula_bin_fast
  - NOTICE:  class_route_term: target=lineitem route=single_hub width=-1 bags=-1 term_atoms=15,16,9,1,7,17,19,11,2,13,6 reason=single_table_formula_bin_fast
  - NOTICE:  class_route_term: target=lineitem route=single_hub width=-1 bags=-1 term_atoms=14,17,19,20,18 reason=single_table_formula_bin_fast
  - NOTICE:  class_route_term: target=lineitem route=single_hub width=-1 bags=-1 term_atoms=14,13,12,21,1,6 reason=single_table_formula_bin_fast
- q3:
  - (none)
- q6:
  - (none)
- q10:
  - (none)
- q11:
  - (none)
