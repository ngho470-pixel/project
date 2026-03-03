# Stage 8A: Projection Aggregation via Per-Signature CTID Masks

## Scope
Stage 8A changes only projection realization (`ActiveSig[target] -> block_words`) and profiling counters.

Unchanged:
- policy semantics (`col op const`, `col op col`, `AND/OR`)
- SAT/Tseitin + OR selectors + exact model enumeration / OR-union
- all-table `ActiveSig` + Stage10R2 pair-bundle propagation
- artifact formats (`CB04/CC04`, domain dicts, rank)
- query-local cache rule (no cross-query caching)

## Exactness (unchanged)
For one SAT model `M`, projection computes:

`Allow(T|M) = union_{sid in ActiveSig[T]} { ctid(rid) | rid in Class(T,sid) }`

Global allow remains OR-union across models.

The optimization is purely an implementation change:
- precomputed sparse per-signature CTID masks
- OR-only projection in the hot path
- idempotent skipping of signatures already OR-ed into the formula-global allow

## Data Structure: Signature CTID Mask Cache (query-local)
The existing `SignatureCacheEntry` already stores sparse CTID masks per signature:
- `sig_mask_offsets[sid..sid+1]`
- `sig_mask_blocks[i]`
- `sig_mask_word_idx[i]`
- `sig_mask_word_vals[i]`

This is a sparse `(blk, word_index, word_value)` representation.

Build path:
- `build_signature_cache_entry(...)` computes signature row classes and CTID mask triples
- cache is query-local in `Loaded::signature_cache`

## Projection Algorithm (Stage 8A)
### Before
Projection OR-ed per-signature masks (fast path), but re-processed the same signatures across SAT models.

### After
Within `eval_formula_root_words(...)`, maintain query-local/per-formula:
- `already_projected_sig_by_schema[(table|schema)] -> TokenBitset`

For each SAT model term:
- compute `active_sig`
- project only signatures not yet present in the schema-local `already_projected_sig`
- mark newly projected signatures as seen

This is exact because OR-union is idempotent.

## Implementation Notes
- The dedup key is `signature_cache_key(table, schema_cols)`.
- `term_has_rows` semantics are preserved:
  - a term can have rows even if all of its signatures were already projected by a previous model
  - this is tracked independently from "new mask OR work"
- No DFS/backtracking introduced.
- No heuristic caps introduced.

## Counters Added
Added to policy profile output (`policy_profile_query` and `policy_profile`):
- `proj_sig_total`
- `proj_sig_new`
- `proj_sig_skipped`
- `sigmask_cache_hits`
- `sigmask_cache_misses`
- `sigmask_build_ms`
- `sigmask_bytes`

Existing counters retained:
- `proj_sig_count` (actual signatures merged into `block_words`)
- `proj_mask_or_ops`
- `proj_rid_iters`
- `bytes_sig_ctid_masks`

## Current Validation Status
Validated locally:
- build passes (`make -C custom_filter -j4`)
- Stage 9 correctness on `tpch0_1` passes (policies `21..30`)
- local sweep smoke (`tpch0_1`, `K=10`, policies `11..20`, `q1`) shows new counters populated and non-zero skip count

Requested `drona/tpch1` perf gate is pending from this shell because SSH auth/tunnel is not currently available.
