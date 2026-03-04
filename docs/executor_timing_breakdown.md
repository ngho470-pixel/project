# Executor Timing Breakdown

This documents strict-mode timing counters emitted from `custom_filter/custom_filter.c` and parsed by `scripts/gate_stage03.py`.

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

Per execution, `cf_reset_query_exec_metrics(...)` clears runtime counters in `ExecutorStart` before the query runs, so metrics are execution-scoped even when query-state is reused.

`policy_profile` and `policy_profile_exec_stage03` carry per-query aggregates; `scripts/gate_stage03.py` reads these into CSV.

## Stage03 Fields

`policy_profile_exec_stage03` includes:

- `policy_eval_ms_total`
- `artifact_load_ms`, `artifact_bytes_read`
- `allow_build_ms`, `executor_init_ms_ours`
- `custom_scan_total_ms`, `custom_scan_overhead_ms`
- `child_exec_ms`, `ctid_extract_ms`, `ctid_to_rid_ms`, `allow_check_ms`, `projection_ms`
- `tid_fetch_ms`, `tid_heap_fetch_ms`, `tid_slot_store_ms`, `tid_visibility_ms`
- aliases: `tid_pages_read_ms`, `tid_tuple_extract_ms`
- `tid_blocks_touched`, `tid_offsets_total`

## Consistency Rule

For strict runs, use:

`custom_scan_total_ms ~= child_exec_ms + ctid_extract_ms + ctid_to_rid_ms + allow_check_ms + projection_ms + tid_fetch_ms + custom_scan_overhead_ms`

A large residual indicates uninstrumented overhead and should be investigated.
