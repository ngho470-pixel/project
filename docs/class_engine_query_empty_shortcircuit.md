# Class Engine Query Empty Short-Circuit

## Goal
When strict class-engine policy evaluation proves an empty allow-set for at least one base relation, skip executing the whole query plan when it is semantically safe.

## Correctness condition
Short-circuit is enabled only if both hold:

1. `any_empty`: at least one filtered base relation has an empty allow-set.
2. `inner_only_safe`: the plan tree has only inner joins and no node classes currently marked unsafe for plan-level collapse.

Under this condition, replacing execution with an empty result is exact for SELECT because any inner-join composition with one empty input is empty.

## Implementation points

- Query decision is made in `cf_executor_start` after query-state/policy build.
- Plan safety is checked by `cf_plan_inner_only_safe(...)`.
- Empty allow detection is checked by `cf_query_has_empty_allow_set(...)`.
- Query execution bypass is done in `cf_executor_run(...)`:
  - set `es_processed = 0`
  - increment query short-circuit counters
  - return without invoking normal plan execution.

## New policy profile counters
Emitted in `policy_profile`:

- `query_short_circuit_empty` (`0|1`)
- `query_short_circuit_reason`
- `query_short_circuit_ms`
- `query_short_circuit_hits`

Existing scan-level counters remain:

- `scan_mode_empty_tables`
- `empty_short_circuit_tables`
- `empty_short_circuit_ms`

## Strict invariants
Strict mode still requires:

- `proj_sig_count=0`
- `proj_mask_or_ops=0`
- `proj_rid_iters=0`

## Notes
This change is orthogonal to class TD/DP correctness: it only short-circuits execution after policy evaluation has already produced exact allow information.
