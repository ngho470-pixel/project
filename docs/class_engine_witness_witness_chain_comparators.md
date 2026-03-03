# Class Engine Witness-Witness Chain Comparators (Stage 3B)

## Scope
- Route: `tree` only (acyclic factor graph).
- Comparator endpoints: both endpoints are witnesses (neither endpoint is the target table).
- Endpoint connectivity: non-adjacent endpoints connected by a unique tree path.
- Operators: `=`, `!=`, `<`, `<=`, `>`, `>=`.
- NULL semantics: NULL token on either side is treated as false.
- Strict invariants unchanged: `proj_sig_count=0`, `proj_mask_or_ops=0`, `proj_rid_iters=0`.

## Semantics
For a witness-witness comparator atom `U.x θ V.y`, row feasibility for table `U` must include:
1. local table predicates on `U`,
2. domain-message membership constraints on `U`,
3. existence of at least one feasible `V` witness row on the unique path key,
4. comparator truth `tok(U.x) θ tok(V.y)` under SQL NULL-false semantics.

The comparator cannot be deferred to final target stamping, because both endpoints are witnesses.

## Summary Representation
For each key `K` (tree path key coordinate), build existential summaries over feasible witness rows:
- ordered ops: `min_rank[K]`, `max_rank[K]`
- equality: `eq_set[K]` (token bitset)
- inequality: `(neq_cnt[K], neq_one[K])` with capped distinct count:
  - accept `x` iff `cnt>=2` OR (`cnt==1` AND `one!=x`)

These summaries are exact existential summaries (rows already satisfy local atoms + domain-message constraints).

## Chain Composition Over Multi-Hop Tree Paths
Given target-side endpoint `U` and witness-side endpoint `V`, orient the unique path from `U` to `V`:
- domains: `D0, D1, ..., Dm` (with `D0` adjacent to `U`, `Dm` adjacent to `V`)
- bridge tables: `B0, B1, ..., Bm-1`

Algorithm:
1. Build base summary at `V`, keyed by `Dm`.
2. For `j = m-1 ... 0`, compose through bridge table `Bj`:
   - input summary keyed by `D(j+1)`
   - scan feasible rows of `Bj` (bin-driven by smallest available inbound domain message)
   - for each row, read `(tok(Dj), tok(D(j+1)))`
   - merge summary state from key `tok(D(j+1))` into output key `tok(Dj)`
3. Final composed summary is keyed by `D0` (the key visible at `U`).
4. While emitting table messages for `U`, accept/reject each row using the composed summary and row token `tok(U.x)`.

This is exact on trees by standard CSP/tree DP composition: existential support composes along the unique path without row-pair materialization.

## Complexity
- Base summary build: `O(feasible rows of V scanned through bins)`.
- Each bridge step: `O(feasible rows scanned in that bridge table)`.
- Comparator row checks: `O(1)` per candidate `U` row after summary build.
- Total: linear in scanned bin slices along the path, with path length factor.

## Implementation Mapping
- Comparator plan path metadata:
  - `custom_filter/policy.cpp` `Pf2TreeComparatorPlan`
  - fields: `witness_witness_chain`, `path_domain_ids_lr`, `path_bridge_tables_lr`
- Chain summary builder:
  - `custom_filter/policy.cpp`
  - `pf2_tree_build_cmp_summary_chain_key1(...)`
- Witness-row filtering hook:
  - `custom_filter/policy.cpp`
  - `pf2_tree_prepare_witness_cmp_context(...)`
  - `pf2_tree_witness_cmp_filter_row(...)`
- Tree route integration:
  - `custom_filter/policy.cpp`
  - `eval_term_conjunction_pf2_tree(...)`

## Counters
Added counters (emitted in `policy_profile_query`):
- `pf2_cmp_chain_total`
- `pf2_cmp_chain_supported`
- `pf2_cmp_chain_build_ms`
- `pf2_cmp_chain_bridge_rows_scanned`
- `pf2_cmp_chain_compose_steps`
- `pf2_cmp_chain_filter_rows_checked`
- `pf2_cmp_chain_filter_rows_reject`

These complement Stage 3A counters:
- `pf2_cmp_witness_witness_total`
- `pf2_cmp_witness_witness_supported`
- `pf2_cmp_filter_rows_checked`
- `pf2_cmp_filter_rows_reject`
