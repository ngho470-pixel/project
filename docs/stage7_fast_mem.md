# Stage 7 Fast + Memory Design

Stage 7 keeps policy semantics unchanged and only changes query-local in-memory evaluation structures.

## 1) Signature cache layout (`rid_sorted` + `sig_off`)

`custom_filter/policy.cpp` now stores signature classes in compact contiguous arrays:

- `row_offsets[sid]` (`sig_off`): start index per signature ID
- `rows_flat` (`rid_sorted`): concatenated RID slices grouped by signature ID
- signature `sid` rowlist is `rows_flat[row_offsets[sid] : row_offsets[sid+1]]`

This replaces nested per-signature rowlist structures and is the canonical in-memory representation.

Additional Stage 7 memory tightening:

- `sid_by_rid` is no longer retained in cache entries after build (temporary only during construction).
- one canonical signature schema per table is used inside a query to maximize signature cache reuse across SAT models.

## 2) Direct projection to CTID block words (no target RID bitmap by default)

For each SAT model term result:

1. iterate active target signature IDs,
2. expand RID slices from `rows_flat/row_offsets`,
3. map RID -> `(blk,off)` via `*_ctid`,
4. set sparse `block_words` bits directly.

Default exact path does not allocate an `O(nrows)` target RID bitmap.

Evidence counter:

- `target_rid_bitmap_bytes=0` on Stage 7 profiled queries.

## 3) Adaptive domain/signature sets

`TokenBitset` is adaptive:

- dense representation (`vector<uint64_t>`) at high density,
- sparse representation (`vector<uint32_t>`) at low density,
- hysteresis-based rebalance to avoid thrashing.

Instrumentation added:

- `active_sig_dense_count`, `active_sig_sparse_count`, `active_sig_density_sum`
- `domain_set_dense_count`, `domain_set_sparse_count`, `domain_set_density_sum`

## 4) Streaming decode for signature construction

Signature build uses already-decoded needed columns and builds signature IDs in streaming passes.
No row-major `decoded_cols[rid][*]` table-of-rows is constructed.

## 5) Sparse block words

`block_words` is sparse:

- only blocks with at least one allowed tuple are materialized,
- final runtime uses `(block_ids, block_words)` compact arrays.

Instrumentation added:

- `block_words_blocks_allocated`
- `block_words_total_blocks`

## 6) Stage 7 observed effects (tpch1, K=5, policy_ids=1..5)

- signature cache memory for q1/q3/q6 dropped from `899,569,476` to `239,977,172` bytes.
- term code scans dropped from `8` to `1` (`signature_cache_hits=11`, `signature_cache_misses=1`).
- `target_full_row_scans=0` retained.
- `project_ms` reduced materially but remains the dominant cost center.

See `logs/stage7_perf.md` and `logs/stage7_perf.csv` for full before/after counters.
