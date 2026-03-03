# Stage 8B: Dense `block_words` Projection Accumulator

## Goal
Reduce `project_ms` / `project_row_ms` by removing hash-map and sparse-block lookup overhead in the hot projection OR loop, without changing policy semantics.

Projection semantics remain exact:
- `Allow(T|M) = ⋃_{sid in ActiveSig[T]} CTIDs(Class(T,sid))`
- `Allow(T) = ⋃_M Allow(T|M)`

## Change (Representation Only)
The projection destination `block_words` accumulator is now a dense cache-friendly array during policy evaluation:
- allocate `dense_words[nblocks * nwords_per_block]` (zero-initialized)
- index as `dense_words[blk * nwords_per_block + word_idx]`
- projection update is a direct OR:
  - `dense_words[blk*nwords_per_block + word_idx] |= word_mask`

This replaces the previous sparse hash-map insertion/lookup in the hot loop.

## What Did Not Change
- SAT/Tseitin + OR selectors + model enumeration until UNSAT
- all-table `ActiveSig` + Stage10R2 pair-bundle propagation
- artifact formats (`CB04/CC04`, domain dicts, rank artifacts, CTID artifacts)
- query-local cache scope only
- exactness (no sampling, no caps, no approximations)

## Data Structure Notes
`SparseBlockWords` API is retained for compatibility with the rest of the engine and executor interface, but its in-memory storage used during projection is now dense-backed (`std::vector<uint64_t>`). The final exported flat `(words, block_ids)` representation remains unchanged for executor use.

## Counters Added
The profile now records dense accumulator shape and footprint:
- `block_words_dense_bytes`
- `block_words_nblocks`
- `block_words_nwords_per_block`

Existing projection counters retained:
- `proj_mask_or_ops`
- `proj_sig_total`, `proj_sig_new`, `proj_sig_skipped`
- `project_ms`, `project_row_ms`

## Expected Effect
This change targets constant-factor overhead in projection:
- same number of logical OR operations (`proj_mask_or_ops` similar)
- lower per-op cost due to contiguous memory writes and no hash-map churn
- reduced `project_ms` and `policy_total_ms`, especially on cross-table policy windows with many signature-mask OR merges

## Caveat (Known, pre-existing)
`proj_rid_iters` may remain non-zero in exact mode due the dependency `restrict_bits` RID path used for policy-target dependency ordering. Stage 8B does not change that path.
