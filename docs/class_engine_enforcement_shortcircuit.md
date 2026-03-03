# Class Engine Enforcement Short-Circuit

## Objective
When class-engine policy evaluation produces an empty allow-set for a target relation, executor must not scan heap tuples.

This is exact under class semantics:
- policy phase computes `AllowCTID(T)` exactly
- if `AllowCTID(T) = ∅`, scan result is empty regardless of query quals

## Implementation

### Scan mode extension
`custom_filter/custom_filter.c` now supports three runtime scan modes:
- `FILTER`: normal tuple-by-tuple membership check against block words
- `TID`: sparse tid-driven fetch path for SeqScan
- `EMPTY`: immediate empty result path (no child scan / heap fetch)

### Empty allow-set detection
Each `TableFilterState` now stores:
- `allowed_rows` = popcount of allow block words
- `allow_is_empty`

`allow_is_empty` is true if effective allow-set has no CTIDs.

### Decision point
`cf_update_scan_mode(...)` sets mode and logs one per-table decision:

`scan_mode_decision: rel=<T> mode=<EMPTY|TID|FILTER> allow_rows=<...> allow_blocks=<...> relpages=<...> density=<...> reason=<...>`

### Short-circuit execution
In `cf_exec(...)`, if `scan_mode == EMPTY`:
- return `ExecClearTuple(...)` immediately
- do not call `ExecProcNode(child)`
- do not touch heap tuples

## Counters
Executor profile (`policy_profile:`) includes:
- `scan_mode_empty_tables`
- `empty_short_circuit_tables`
- `empty_short_circuit_ms`

Also retained:
- `scan_mode_tid_tables`
- `scan_mode_filter_tables`

Strict invariants remain:
- `proj_sig_count=0`
- `proj_mask_or_ops=0`
- `proj_rid_iters=0`

## Additional consistency fix
TD reduction counter in `custom_filter/policy.cpp` now reports exact pair shrink:

`class_td_reduction_removed_pairs = class_td_pairs_before - class_td_pairs_after`

This aligns counters with adaptive reduction decisions.
