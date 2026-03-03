# Class Engine Witness-Witness Comparators (Stage 3A)

## Scope
This stage extends strict class-engine comparator handling to allow cross-table comparators where neither endpoint is the target table, with these limits:

- route: `tree` (acyclic) and existing `cycle_rect` unchanged
- comparator endpoints: witness-witness
- tree support: adjacent-only (shared separator key directly), key arity `1`
- operators: `=`, `!=`, `<`, `<=`, `>`, `>=`
- NULL token semantics: NULL -> UNKNOWN -> false

Unsupported in strict mode (fail-loud):

- non-adjacent witness-witness comparators in tree route
- witness-witness comparator key arity `> 2` (and in Stage 3A tree path, effectively `> 1`)

## Semantics
For one conjunction term, witness-witness comparator feasibility must be enforced during propagation, not only at target stamping.

For comparator `U.x θ V.y` keyed by separator key `K`:

1. Build summary on `V` keyed by `K`, over witness-feasible rows under current inbound messages and local predicates.
2. While scanning candidate rows of `U` to emit table->domain messages, reject `U` rows that fail summary acceptance for `x(u)` at key `K(u)`.

This preserves existential witness semantics:

- row in `U` contributes only if there exists compatible witness support in `V` for the same key.

## Summary forms reused
Existing comparator summaries are reused unchanged:

- `=`: `eq_set[K]`
- ordered: `min_rank[K]`, `max_rank[K]`
- `!=`: `(neq_cnt[K], neq_one[K])`

Acceptance for `!=` remains:

- accept if `neq_cnt >= 2`
- accept if `neq_cnt == 1 && neq_one != x`
- reject otherwise

## Code mapping
- comparator planning and shape gate:
  - `custom_filter/policy.cpp` `pf2_tree_detect_pattern(...)`
  - witness-witness comparators now represented in `Pf2TreeComparatorPlan::witness_witness`
- message-time comparator filtering:
  - `custom_filter/policy.cpp` `pf2_tree_prepare_witness_cmp_context(...)`
  - `custom_filter/policy.cpp` `pf2_tree_witness_cmp_filter_row(...)`
  - `custom_filter/policy.cpp` `pf2_tree_emit_table_messages(...)`
- target-endpoint projection checks remain:
  - `custom_filter/policy.cpp` `pf2_cmp_summary_accept_target_row(...)`
  - `custom_filter/policy.cpp` `eval_term_conjunction_pf2_tree(...)`

## New counters
Added to `policy_profile_query`:

- `pf2_cmp_witness_witness_total`
- `pf2_cmp_witness_witness_supported`
- `pf2_cmp_filter_rows_checked`
- `pf2_cmp_filter_rows_reject`

These are emitted alongside existing invariant counters:

- `proj_sig_count`
- `proj_mask_or_ops`
- `proj_rid_iters`

## Complexity
- summary build: one witness-side pass per relevant comparator/table-update context
- filter check: O(1) per candidate scanned row after summary materialization
- no fallback to non-class engines

