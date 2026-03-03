# Class Engine TD-Cycle Minimization

## Scope
This stage reduces TD-cycle runtime cost by shrinking feasible separator assignments before and during DP, while preserving exactness.

Strict contract remains unchanged:
- class-engine routes only in strict mode
- SAT is selector-only
- no fallback
- projection invariants must stay zero: `proj_sig_count=0`, `proj_mask_or_ops=0`, `proj_rid_iters=0`

## 4.2A Exact Reduction Prepass

### What runs
For `td_cycle` terms (`width <= 2`), an exact semijoin-style prepass runs before DP.

- GUC: `custom_filter.class_td_reduction=on|off`
- Default behavior:
  - strict mode + unset GUC => reduction enabled
  - explicit `off` disables

### Algorithm
Given factor relations (token tuple sets):
1. Compute variable support bitsets by intersecting supports across incident relations.
2. Apply comparator-support pruning on those supports (exact, no approximation).
3. Filter each relation by support membership.
4. Apply comparator tuple filtering to each relation.
5. Repeat pass 2 only if pass-1 shrink ratio >= 5%.

This prepass only removes infeasible assignments; semantics are unchanged.

### Counters
- `class_td_reduction_passes`
- `class_td_reduction_ms`
- `class_td_reduction_removed_pairs`
- `class_td_pairs_before`
- `class_td_pairs_after`
- `class_td_cmp_filter_ms`
- `class_td_cmp_filter_removed_pairs`

## 4.2B Projection-First Elimination Direction

For width-2 TD-cycle terms, elimination direction is chosen exactly (cost-only optimization):
- build candidate elimination order (excluding protected target/comparator vars)
- estimate peak intermediate relation size for:
  - forward order
  - reversed order
- select lower-peak direction

No semantic effect; only changes computation order.

### Counters
- `class_td_elim_order` (`0=forward`, `1=reverse`)
- `class_td_peak_msg_pairs`
- `class_td_peak_msg_bytes`

## 4.2C Comparator-Aware Early Filtering
Comparator pruning is applied in prepass relation filtering and carried into DP joins/projections.

Comparator checks remain exact:
- ordered comparators use rank semantics
- equality uses token membership
- inequality uses existing exact semantics

### Counter evidence
- `class_td_cmp_filter_ms`
- `class_td_cmp_filter_removed_pairs`

## Runtime Files
- Engine implementation: `custom_filter/policy.cpp`
- Correctness runner: `scripts/class_td_cycle_correctness_verify.py`
- Perf runner: `scripts/class_td_cycle_perf.py`

## Deliverables
- `logs/class_td_cycle_min_correctness.csv`
- `logs/class_td_cycle_min_correctness.md`
- `logs/class_td_cycle_min_perf.csv`
- `logs/class_td_cycle_min_perf.md`
