# Toy Glass-Box Audit

- database: `toy_tpch_glassbox`
- policy file: `logs/toy_policy.txt`
- artifacts dump dir: `logs/toy_artifacts`
- results csv: `logs/toy_results.csv`

## 0) Toy Data Loaded

- lineitem rows: [(10, 1), (20, 2), (10, 3), (30, 1), (30, 2), (40, 1), (30, 3)]
- orders rows: [(10, 100, 'O'), (20, 100, 'F'), (30, 200, 'O'), (40, 300, 'F')]
- customer rows: [(100, 'AUTOMOBILE'), (200, 'HOUSEHOLD'), (300, 'AUTOMOBILE')]

## 1) Policy

- `P1`: `lineitem.l_orderkey = orders.o_orderkey AND orders.o_orderstatus = 'O'`
- `P2`: `lineitem.l_orderkey = orders.o_orderkey AND orders.o_custkey = customer.c_custkey AND customer.c_mktsegment = 'AUTOMOBILE'`
- `P = P1 OR P2`
- policy line used by engine: `1. lineitem : (lineitem.l_orderkey = orders.o_orderkey AND orders.o_orderstatus = 'O') OR (lineitem.l_orderkey = orders.o_orderkey AND orders.o_custkey = customer.c_custkey AND customer.c_mktsegment = 'AUTOMOBILE')`
- RLS rewritten predicate actually installed: `EXISTS (SELECT 1 FROM customer, orders WHERE (lineitem.l_orderkey = orders.o_orderkey AND orders.o_orderstatus = 'O') OR (lineitem.l_orderkey = orders.o_orderkey AND orders.o_custkey = customer.c_custkey AND customer.c_mktsegment = 'AUTOMOBILE'))`

## 2) Artifact Build Output

| Artifact | Where written in builder |
|---|---|
| `meta/join_classes` | `artifact_builder/artifact_builder.c:1095` |
| `meta/col_domain` | `artifact_builder/artifact_builder.c:1125` |
| `meta/cols/<table>` | `artifact_builder/artifact_builder.c:1197` |
| `<table>_ctid` | `artifact_builder/artifact_builder.c:1264` + `artifact_builder/artifact_builder.c:1426` |
| `<table>_code_chunk_i` | `artifact_builder/artifact_builder.c:247` (`flush_code_chunk`) |
| `<table>_code_base` (CB03 manifest) | `artifact_builder/artifact_builder.c:1413` |
| `dict/domain/<id>` | `artifact_builder/artifact_builder.c:1452` |
| `dict/<table>/<col>` | `artifact_builder/artifact_builder.c:1486` |
| `meta/dict_rank/domain/<id>` | `artifact_builder/artifact_builder.c:1469` |
| `rank/domain/<id>` (only if ordered compare used) | `artifact_builder/artifact_builder.c:1470` + `artifact_builder/artifact_builder.c:695` |

### Domain Grouping / Join Classes

- parsed `meta/join_classes`: `{"0": ["customer.c_custkey", "orders.o_custkey"], "1": ["customer.c_mktsegment"], "2": ["lineitem.l_orderkey", "orders.o_orderkey"], "3": ["orders.o_orderstatus"]}`
- parsed `meta/col_domain`: `{"customer.c_custkey": 0, "customer.c_mktsegment": 1, "lineitem.l_orderkey": 2, "orders.o_custkey": 0, "orders.o_orderkey": 2, "orders.o_orderstatus": 3}`
- raw files:
  - `logs/toy_artifacts/meta_join_classes.txt`
  - `logs/toy_artifacts/meta_col_domain.txt`

### Dictionaries

- dict/domain/0: {100->0, 200->1, 300->2}
- dict/domain/1: {AUTOMOBILE->0, HOUSEHOLD->1}
- dict/domain/2: {10->0, 20->1, 30->2, 40->3}
- dict/domain/3: {O->0, F->1}
- dict/customer/c_mktsegment: {AUTOMOBILE->0, HOUSEHOLD->1}
- dict/orders/o_orderstatus: {O->0, F->1}
- `lineitem.l_linenumber` is **not materialized** in artifacts for this run because the builder includes only policy-scoped columns; logical mapping from data would be `{1->0, 2->1, 3->2}`.

### Code Matrices (tokenized)

- `lineitem` shape: `7 x 1`
  - columns: `['lineitem.l_orderkey']`
  - note: only `lineitem.l_orderkey` appears because `l_linenumber` is outside policy scope in this toy policy.
  - manifest: `CB03 total_rows=7 chunk_rows=1000000 ntoks=1 chunks=1`
  - dump: `logs/toy_artifacts/lineitem_code_matrix.csv`
- `orders` shape: `4 x 3`
  - columns: `['orders.o_custkey', 'orders.o_orderkey', 'orders.o_orderstatus']`
  - manifest: `CB03 total_rows=4 chunk_rows=1000000 ntoks=3 chunks=1`
  - dump: `logs/toy_artifacts/orders_code_matrix.csv`
- `customer` shape: `3 x 2`
  - columns: `['customer.c_custkey', 'customer.c_mktsegment']`
  - manifest: `CB03 total_rows=3 chunk_rows=1000000 ntoks=2 chunks=1`
  - dump: `logs/toy_artifacts/customer_code_matrix.csv`

### CTID Artifacts (RID -> CTID)

- `lineitem_ctid` rows=7 dump: `logs/toy_artifacts/lineitem_ctid.csv`
  - first pairs: `[(0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (0, 6), (0, 7)]`
- `orders_ctid` rows=4 dump: `logs/toy_artifacts/orders_ctid.csv`
  - first pairs: `[(0, 1), (0, 2), (0, 3), (0, 4)]`
- `customer_ctid` rows=3 dump: `logs/toy_artifacts/customer_ctid.csv`
  - first pairs: `[(0, 1), (0, 2), (0, 3)]`

## 3) Policy Compilation + Evaluation Trace

### AST / Atoms as seen by engine

- `CF_POLICY_AST` (Q1 ours): `NOTICE:  CF_POLICY_AST target=lineitem perm=1 rest=0 y0=0 ast=y4 and y2 or y4 and y3 and y1`
- atom lines:
```text
NOTICE:  policy_eval: atom y1 = const:customer.c_mktsegment|=|AUTOMOBILE
NOTICE:  policy_eval: atom y2 = const:orders.o_orderstatus|=|O
NOTICE:  policy_eval: atom y3 = join:customer.c_custkey=orders.o_custkey
NOTICE:  policy_eval: atom y4 = join:lineitem.l_orderkey=orders.o_orderkey
NOTICE:  policy_eval: atom y1 = const:customer.c_mktsegment|=|AUTOMOBILE
NOTICE:  policy_eval: atom y2 = const:orders.o_orderstatus|=|O
NOTICE:  policy_eval: atom y3 = join:customer.c_custkey=orders.o_custkey
NOTICE:  policy_eval: atom y4 = join:lineitem.l_orderkey=orders.o_orderkey
NOTICE:  policy_eval: atom y1 = const:customer.c_mktsegment|=|AUTOMOBILE
NOTICE:  policy_eval: atom y2 = const:orders.o_orderstatus|=|O
NOTICE:  policy_eval: atom y3 = join:customer.c_custkey=orders.o_custkey
NOTICE:  policy_eval: atom y4 = join:lineitem.l_orderkey=orders.o_orderkey
NOTICE:  policy_eval: atom y1 = const:customer.c_mktsegment|=|AUTOMOBILE
NOTICE:  policy_eval: atom y2 = const:orders.o_orderstatus|=|O
NOTICE:  policy_eval: atom y3 = join:customer.c_custkey=orders.o_custkey
NOTICE:  policy_eval: atom y4 = join:lineitem.l_orderkey=orders.o_orderkey
```
- profile notices from same run:
```text
NOTICE:  policy_profile_query: K=0 query_id= total_ms=2.487 load_ms=0.197 local_ms=0.000 prop_ms=0.015 decode_ms=0.002 sat_calls=3 cache_hits=0 closure_tables=0 filtered_targets=1 clause_plan_count_max=4 prop_join_scans_total=16 unique_join_struct_sigs_max=3 signature_cache_hits=1 signature_cache_misses=4 term_code_scans=4 target_full_row_scans=0 target_rid_bitmap_bytes=0 signature_cache_bytes=587 active_sig_dense_count=2 active_sig_sparse_count=0 active_sig_density_sum=1.250000 domain_set_dense_count=5 domain_set_sparse_count=0 domain_set_density_sum=2.916667 block_words_blocks_allocated=1 block_words_total_blocks=1 block_words_dense_bytes=64 block_words_nblocks=1 block_words_nwords_per_block=8 proj_sig_count=4 proj_sig_total=5 proj_sig_new=4 proj_sig_skipped=1 proj_mask_or_ops=4 proj_rid_iters=0 proj_rid_iters_scan_enforcement=0 proj_rid_iters_dependency=0 canon_term_map_cache_hits=0 canon_term_map_cache_misses=0 canon_term_map_build_ms=0.000 canon_term_map_bytes=0 sigmask_cache_hits=1 sigmask_cache_misses=4 sigmask_build_ms=0.003 sigmask_bytes=271 bytes_sig_ctid_masks=271 bytes_block_words=68 bytes_artifact_buffers_retained=0 bytes_decoded_buffers_retained=0 witness_activesig_tables=5 witness_sig_count_total=19 support_recompute_ms=0.005 sig_prune_ms=0.001 pair_bundle_count=3 pair_bundle_build_ms=0.005 pair_bundle_prune_ms=0.002 pair_bundle_keys_total=28 pair_bundle_pruned_sigs_total=0 pair_bundle_iters=4 qual_atoms_total=0 qual_atoms_applied=0 qual_pruned_sigs=0 qual_prune_ms=0.000 restrict_sig_tables=0 restrict_sig_schema_cols_total=0 restrict_sig_bytes_total=0 restrict_sig_apply_ms=0.000 restrict_term_apply_ms=0.000 restrict_term_sigs_kept=0 restrict_term_sigs_dropped=0
NOTICE:  policy_profile: eval_ms=0.173 artifact_load_ms=0.312 artifact_parse_ms=0.197 atoms_ms=0.012 propagate_ms=0.015 project_ms=2.040 project_mask_ms=0.000 project_row_ms=0.714 project_mask_bytes=0 project_n_join_evals_max=2 project_clause_words_max=1 clause_plan_count_max=4 prop_join_scans_total=16 unique_join_struct_sigs_max=3 prop_table_scans=orders:8|customer:4|lineitem:4 signature_cache_hits=1 signature_cache_misses=4 term_code_scans=4 target_full_row_scans=0 target_rid_bitmap_bytes=0 signature_cache_bytes=587 active_sig_dense_count=2 active_sig_sparse_count=0 active_sig_density_sum=1.250000 domain_set_dense_count=5 domain_set_sparse_count=0 domain_set_density_sum=2.916667 block_words_blocks_allocated=1 block_words_total_blocks=1 block_words_dense_bytes=64 block_words_nblocks=1 block_words_nwords_per_block=8 proj_sig_count=4 proj_sig_total=5 proj_sig_new=4 proj_sig_skipped=1 proj_mask_or_ops=4 proj_rid_iters=0 proj_rid_iters_scan_enforcement=0 proj_rid_iters_dependency=0 canon_term_map_cache_hits=0 canon_term_map_cache_misses=0 canon_term_map_build_ms=0.000 canon_term_map_bytes=0 sigmask_cache_hits=1 sigmask_cache_misses=4 sigmask_build_ms=0.003 sigmask_bytes=271 bytes_sig_ctid_masks=271 bytes_block_words=68 bytes_artifact_buffers_retained=0 bytes_decoded_buffers_retained=0 qual_atoms_total=0 qual_atoms_applied=0 qual_pruned_sigs=0 qual_prune_ms=0.000 restrict_sig_tables=0 restrict_sig_schema_cols_total=0 restrict_sig_bytes_total=0 restrict_sig_apply_ms=0.000 restrict_term_apply_ms=0.000 restrict_term_sigs_kept=0 restrict_term_sigs_dropped=0 stamp_ms=0.000 bin_ms=0.000 local_sat_ms=0.000 fill_ms=0.000 prop_ms=0.015 prop_iters=4 decode_ms=0.002 policy_total_ms=2.487 ctid_map_ms=0.000 filter_ms=0.009 child_exec_ms=0.005 ctid_extract_ms=0.000 ctid_to_rid_ms=0.000 allow_check_ms=0.000 projection_ms=0.000 blocks_seen=1 blocks_skipped=0 block_skip_hit_rate=0.000000 scan_mode_tid_tables=0 scan_mode_filter_tables=1 tid_blocks_visited=0 tid_tuples_fetched=0 tid_fetch_ms=0.000 tid_qual_ms=0.000 n_scanned_tables=2 n_policy_targets=1 n_filters=1 bytes_artifacts_loaded=634 bytes_allow=68 bytes_ctid=0 bytes_blk_index=0 rows_seen=7 rows_passed=7 ctid_misses=0 rss_kb_before_eval=26404 rss_kb_after_eval=26404 rss_kb_after_load=27436 rss_kb_after_engine=37212 rss_kb_after_ctid=37212 rss_kb_end=37212 peak_rss_kb_end=37212
NOTICE:  policy_profile_query: K=0 query_id= total_ms=1.589 load_ms=0.173 local_ms=0.000 prop_ms=0.011 decode_ms=0.001 sat_calls=3 cache_hits=0 closure_tables=0 filtered_targets=1 clause_plan_count_max=4 prop_join_scans_total=16 unique_join_struct_sigs_max=3 signature_cache_hits=1 signature_cache_misses=4 term_code_scans=4 target_full_row_scans=0 target_rid_bitmap_bytes=0 signature_cache_bytes=587 active_sig_dense_count=2 active_sig_sparse_count=0 active_sig_density_sum=1.250000 domain_set_dense_count=5 domain_set_sparse_count=0 domain_set_density_sum=2.916667 block_words_blocks_allocated=1 block_words_total_blocks=1 block_words_dense_bytes=64 block_words_nblocks=1 block_words_nwords_per_block=8 proj_sig_count=4 proj_sig_total=5 proj_sig_new=4 proj_sig_skipped=1 proj_mask_or_ops=4 proj_rid_iters=0 proj_rid_iters_scan_enforcement=0 proj_rid_iters_dependency=0 canon_term_map_cache_hits=0 canon_term_map_cache_misses=0 canon_term_map_build_ms=0.000 canon_term_map_bytes=0 sigmask_cache_hits=1 sigmask_cache_misses=4 sigmask_build_ms=0.003 sigmask_bytes=271 bytes_sig_ctid_masks=271 bytes_block_words=68 bytes_artifact_buffers_retained=0 bytes_decoded_buffers_retained=0 witness_activesig_tables=5 witness_sig_count_total=19 support_recompute_ms=0.004 sig_prune_ms=0.001 pair_bundle_count=3 pair_bundle_build_ms=0.005 pair_bundle_prune_ms=0.002 pair_bundle_keys_total=28 pair_bundle_pruned_sigs_total=0 pair_bundle_iters=4 qual_atoms_total=0 qual_atoms_applied=0 qual_pruned_sigs=0 qual_prune_ms=0.000 restrict_sig_tables=0 restrict_sig_schema_cols_total=0 restrict_sig_bytes_total=0 restrict_sig_apply_ms=0.000 restrict_term_apply_ms=0.000 restrict_term_sigs_kept=0 restrict_term_sigs_dropped=0
NOTICE:  policy_profile: eval_ms=0.155 artifact_load_ms=0.120 artifact_parse_ms=0.173 atoms_ms=0.012 propagate_ms=0.011 project_ms=1.245 project_mask_ms=0.000 project_row_ms=0.538 project_mask_bytes=0 project_n_join_evals_max=2 project_clause_words_max=1 clause_plan_count_max=4 prop_join_scans_total=16 unique_join_struct_sigs_max=3 prop_table_scans=orders:8|customer:4|lineitem:4 signature_cache_hits=1 signature_cache_misses=4 term_code_scans=4 target_full_row_scans=0 target_rid_bitmap_bytes=0 signature_cache_bytes=587 active_sig_dense_count=2 active_sig_sparse_count=0 active_sig_density_sum=1.250000 domain_set_dense_count=5 domain_set_sparse_count=0 domain_set_density_sum=2.916667 block_words_blocks_allocated=1 block_words_total_blocks=1 block_words_dense_bytes=64 block_words_nblocks=1 block_words_nwords_per_block=8 proj_sig_count=4 proj_sig_total=5 proj_sig_new=4 proj_sig_skipped=1 proj_mask_or_ops=4 proj_rid_iters=0 proj_rid_iters_scan_enforcement=0 proj_rid_iters_dependency=0 canon_term_map_cache_hits=0 canon_term_map_cache_misses=0 canon_term_map_build_ms=0.000 canon_term_map_bytes=0 sigmask_cache_hits=1 sigmask_cache_misses=4 sigmask_build_ms=0.003 sigmask_bytes=271 bytes_sig_ctid_masks=271 bytes_block_words=68 bytes_artifact_buffers_retained=0 bytes_decoded_buffers_retained=0 qual_atoms_total=0 qual_atoms_applied=0 qual_pruned_sigs=0 qual_prune_ms=0.000 restrict_sig_tables=0 restrict_sig_schema_cols_total=0 restrict_sig_bytes_total=0 restrict_sig_apply_ms=0.000 restrict_term_apply_ms=0.000 restrict_term_sigs_kept=0 restrict_term_sigs_dropped=0 stamp_ms=0.000 bin_ms=0.000 local_sat_ms=0.000 fill_ms=0.000 prop_ms=0.011 prop_iters=4 decode_ms=0.001 policy_total_ms=1.589 ctid_map_ms=0.000 filter_ms=0.007 child_exec_ms=0.003 ctid_extract_ms=0.000 ctid_to_rid_ms=0.000 allow_check_ms=0.000 projection_ms=0.000 blocks_seen=1 blocks_skipped=0 block_skip_hit_rate=0.000000 scan_mode_tid_tables=0 scan_mode_filter_tables=1 tid_blocks_visited=0 tid_tuples_fetched=0 tid_fetch_ms=0.000 tid_qual_ms=0.000 n_scanned_tables=2 n_policy_targets=1 n_filters=1 bytes_artifacts_loaded=634 bytes_allow=68 bytes_ctid=0 bytes_blk_index=0 rows_seen=7 rows_passed=7 ctid_misses=0 rss_kb_before_eval=37212 rss_kb_after_eval=37212 rss_kb_after_load=37212 rss_kb_after_engine=37724 rss_kb_after_ctid=37724 rss_kb_end=38236 peak_rss_kb_end=38236
```

### OR Branch Enumeration in `eval_formula_root_bits`

- code path: `custom_filter/policy.cpp:4686` (`eval_formula_root_bits`), `custom_filter/policy.cpp:4736` (`block_current_branch_model`), `custom_filter/policy.cpp:4754` (`block_path_decisions`).
- this formula has one OR node, so SAT branch vars = 1 and total branch assignments = 2.
- branch decision `var1=true` selects left disjunct (`P1`), then blocks path with clause `[-1]`.
- branch decision `var1=false` selects right disjunct (`P2`), then blocks path with clause `[+1]`.

### Term Trace (token propagation)

| Step | Result |
|---|---|
| `P1` init domain(orderkey) | tokens `[0, 1, 2, 3]` values `['10', '20', '30', '40']` |
| `P1` unary cut `orders.status='O'` | orderkey tokens `[0, 2]` values `['0:10', '2:30']` |
| `P1` projection on lineitem | allowed RIDs `[0, 2, 3, 4, 6]` |
| `P2` init domain(custkey) | tokens `[0, 1, 2]` values `['100', '200', '300']` |
| `P2` unary cut `customer.segment='AUTOMOBILE'` | custkey tokens `[0, 2]` values `['0:100', '2:300']` |
| `P2` bottom-up via `orders(orderkey,custkey)` | orderkey tokens `[0, 1, 3]` values `['0:10', '1:20', '3:40']` |
| `P2` top-down via `orders(orderkey,custkey)` | custkey tokens `[0, 2]` values `['0:100', '2:300']` |
| `P2` projection on lineitem | allowed RIDs `[0, 1, 2, 5]` |
| `P1 OR P2` union | final allowed RIDs `[0, 1, 2, 3, 4, 5, 6]` (all 7 rows) |

## 4) Final Allow Set -> Block Bitmap -> Runtime Check

- allowed lineitem rows (by values):
```text
rid=0 row=(10, 1)
rid=1 row=(20, 2)
rid=2 row=(10, 3)
rid=3 row=(30, 1)
rid=4 row=(30, 2)
rid=5 row=(40, 1)
rid=6 row=(30, 3)
```
- RID bitmap indexes: `[0, 1, 2, 3, 4, 5, 6]`
- lineitem block_words compact (non-zero words only): `{0: ['w0=0x000000000000007f']}`
- sample allowed check: rid=0 -> ctid=(0,1) => allowed=True
- sample denied check (synthetic, because final policy allows all real rows): ctid=(0,8) => allowed=False
- runtime check code path: `custom_filter/custom_filter.c:3470` reads `(blk,off)` from tuple CTID, then `custom_filter/custom_filter.c:3473` calls `cf_allowed_ctid_words(...)`; `custom_filter/custom_filter.c:111` does the bit test.

## 5) Sanity Check vs Ground Truth

- Q1 ours rows:
  - `[(10, 1), (10, 3), (20, 2), (30, 1), (30, 2), (30, 3), (40, 1)]`
  - count/hash: `7 / 74d4400c7477f6bef8268a946ce56a27`
- Q1 rls_with_index rows:
  - `[(10, 1), (10, 3), (20, 2), (30, 1), (30, 2), (30, 3), (40, 1)]`
  - count/hash: `7 / 74d4400c7477f6bef8268a946ce56a27`
- Q2 ours rows:
  - `[(10, 1), (10, 3), (20, 2), (30, 1), (30, 2), (30, 3), (40, 1)]`
  - count/hash: `7 / 74d4400c7477f6bef8268a946ce56a27`
- Q2 rls_with_index rows:
  - `[(10, 1), (10, 3), (20, 2), (30, 1), (30, 2), (30, 3), (40, 1)]`
  - count/hash: `7 / 74d4400c7477f6bef8268a946ce56a27`
- PASS status: Q1=True, Q2=True

## 6) File Pointers

- artifact index: `logs/toy_artifacts/artifact_index.csv`
- raw artifacts: `logs/toy_artifacts/raw`
- query output csv: `logs/toy_results.csv`
