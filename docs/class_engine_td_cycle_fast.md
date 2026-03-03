# Class Engine TD-Cycle Fast Path

## Scope
This note documents the Stage 4.1A/4.1B/4.1D td-cycle runtime changes in `custom_filter/policy.cpp` for strict mode (`route=td_cycle`).

Strict invariants remain unchanged:
- `proj_sig_count=0`
- `proj_mask_or_ops=0`
- `proj_rid_iters=0`

## 1) Message/Relation Representation
Previous td-cycle DP used hash-heavy `unordered_set<vector<int32_t>>` joins/projections.

Current td-cycle uses sorted tuple relations with fixed arity (W<=2 => bag arity <=3):
- `ClassTdRelation.vars`: sorted class-pos variable list
- `ClassTdRelation.tuples`: sorted unique `ClassTdTuple` rows (`uint32_t tok[3]`)
- `ClassTdRelation.has_empty`: arity-0 existential relation

Projection outputs are treated as TD messages and accounted with:
- `class_td_msg_entries_total`
- `class_td_msg_bytes_total`
- `class_td_msg_pairs_total` (arity-2 rows)

## 2) Join/Project Kernels
Core operators are now sort-merge / linear-group kernels:
- join: `class_td_join_two_relations(...)`
  - shared-key index arrays are sorted by separator key
  - groups are merged by two-pointer scans
  - no unordered-map in the hot path
- project-drop/project-keep:
  - tuple rewrite + sort/unique

Timing counters:
- `class_td_join_ms`
- `class_td_project_ms`

## 3) Comparator Integration in TD-Cycle (non-rectangle)
`td_cycle` no longer rejects cross-table comparators by default.

Integration model:
- Cross-table comparators are collected in `ClassTdCyclePattern.cross_table_cmps`
- Comparator edges are added to the TD primal graph
- Comparator constraints are enforced by tuple filtering (`class_td_filter_relation_by_comparators`) during join/project and before final projection to target vars
- Comparators use existing token-level semantics via `token_compare(...)` with rank data for ordered ops

This stays class/token based and does not materialize row-pair joins.

## 4) Semijoin Reduction Prepass
Exact semijoin reduction exists (`class_td_semijoin_reduction`) with counters:
- `class_td_reduction_ms`
- `class_td_reduction_removed_pairs`

In practice on `TDC2` this pass reduced tuples but was net-negative for runtime. It is now **opt-in** via:
- `custom_filter.class_td_reduction=on`

Default is OFF in strict runs.

## 5) Current Complexity Shape
For td-cycle width<=2:
- Relation ops are bounded to tiny tuple arity (<=3)
- Join/project complexity is dominated by sorted-scan costs and output cardinality, not hash table churn
- Message memory is explicit via `class_td_msg_bytes_total`

## 6) Validation Outputs
Generated on drona:
- `logs/class_td_cycle_fast_correctness.csv`
- `logs/class_td_cycle_fast_correctness.md`
- `logs/class_td_cycle_fast_perf.csv`
- `logs/class_td_cycle_fast_perf.md`

Observed in perf log:
- `TDC2` (`route=td_cycle`, width=2 ring) moved from slower-than-RLS to `ours/rls=0.966` in the curated run.
