# tpch0_1 Case B Profile (S_B, baseline=ours, q3)

- db: `tpch0_1`
- policy_ids: `1,2,3,4,5,6,7,8,9,10`
- setup_ms: `3054.269`
- strict_mode: `on` (ours baseline session setup)

## Per Query
- q3: status=ok ms=3434.859 rss_kb=159224 sat_ms=0.000 sat_models_total=0 sat_conflicts=0 sat_decisions=0 terms_total=10 term_eval_ms_total=124.292 combine_algebra_ms=0.832 allow_rows_total=40243 route_terms={"single_hub": 10} bin_ops_total=426089 bins_touched_total=426042 bin_rids_scanned_total=7661176 heap_rows_scanned_total=0 allow_cache_hit=0 allow_cache_miss=2 allow_cache_build_ms=128.041 inv_proj_sig=0 inv_proj_mask=0 inv_proj_rid=0 error_type= error_msg=

## Raw Route Lines
- q3:
  - NOTICE:  class_route_term: target=customer route=single_hub width=-1 bags=-1 term_atoms=4,9,10,14 reason=single_table_formula_bin_fast
  - NOTICE:  class_route_term: target=customer route=single_hub width=-1 bags=-1 term_atoms=13,12,22,20,11,10,2 reason=single_table_formula_bin_fast
  - NOTICE:  class_route_term: target=customer route=single_hub width=-1 bags=-1 term_atoms=7,8 reason=single_table_formula_bin_fast
  - NOTICE:  class_route_term: target=customer route=single_hub width=-1 bags=-1 term_atoms=3,1,21,19 reason=single_table_formula_bin_fast
  - NOTICE:  class_route_term: target=customer route=single_hub width=-1 bags=-1 term_atoms=7,4,9,6,8,5,15,16,17,18 reason=single_table_formula_bin_fast
  - NOTICE:  class_route_term: target=lineitem route=single_hub width=-1 bags=-1 term_atoms=35,29 reason=single_table_formula_bin_fast
  - NOTICE:  class_route_term: target=lineitem route=single_hub width=-1 bags=-1 term_atoms=26,23,32,27,25,30 reason=single_table_formula_bin_fast
  - NOTICE:  class_route_term: target=lineitem route=single_hub width=-1 bags=-1 term_atoms=37,38,31,23,29,39,41,33,24,35,28 reason=single_table_formula_bin_fast
  - NOTICE:  class_route_term: target=lineitem route=single_hub width=-1 bags=-1 term_atoms=36,39,41,42,40 reason=single_table_formula_bin_fast
  - NOTICE:  class_route_term: target=lineitem route=single_hub width=-1 bags=-1 term_atoms=36,35,34,43,23,28 reason=single_table_formula_bin_fast
