# Executor Timing Breakdown

This documents strict-mode custom scan timing counters emitted in `policy_profile` from `custom_filter/custom_filter.c`.

## Counter Sources

- `custom_scan_total_ms`: inclusive time spent in `ExecCustomScan` across calls (sum of `CfExec.row_validation_ms`).
- `custom_scan_overhead_ms`: residual after subtracting major measured sub-stages from `custom_scan_total_ms`.
- `child_exec_ms`: time in `ExecProcNode(child)` for FILTER-mode pulls.
- `child_next_calls_total`: number of child `ExecProcNode` calls.
- `ctid_extract_ms`: CTID extraction/decode time from child slots.
- `ctid_to_rid_ms`: CTID->RID mapping time.
- `allow_check_ms`: allow-set membership checks against block words.
- `projection_ms`: output slot/project/store time.
- `tid_fetch_ms`: total TID-path fetch time.
- `tid_heap_fetch_ms`: heap fetch part of TID-path.
- `tid_visibility_ms`: visibility-check part of TID-path.
- `tid_slot_store_ms`: tuple deform/store/project in TID-path.

## Aggregation

Per-node counters are collected in `CfExec` and aggregated in `cf_end(...)` into `PolicyQueryState`.

`policy_profile` logs per-query aggregates. `scripts/gate_stage01.py` copies these fields into CSV.

## Consistency Rule

For strict runs, use:

`custom_scan_total_ms ~= child_exec_ms + ctid_extract_ms + ctid_to_rid_ms + allow_check_ms + projection_ms + tid_fetch_ms + custom_scan_overhead_ms`

A large residual indicates uninstrumented overhead and should be investigated.

