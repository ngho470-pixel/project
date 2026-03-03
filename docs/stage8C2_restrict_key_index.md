# Stage 8C.2: Restriction Key Index (Query-Local, No RID Dependency Chaining)

## Goal
Eliminate Stage 8C.1's expensive canonical->term image construction (`RestrictTerm` bitsets) while preserving:
- strict exact semantics
- `proj_rid_iters_dependency = 0`
- query-local-only caches

## What Changed
Stage 8C.2 replaces hot-path `RestrictTerm(U,t)` construction in witness initialization with a query-local restriction key index built from `RestrictCanon(U)` canonical signatures.

### New cache (query-local)
- `RestrictKeyIndexCacheEntry`: `custom_filter/policy.cpp:1484`
- `Loaded.restrict_key_index_cache`: `custom_filter/policy.cpp:1582`

Cache key:
- table name
- canonical schema (`RestrictSigState.schema_cols`)
- bundle key column list (table meta-col indexes)

Stored value:
- `key_to_canon_sids[key_tuple] -> [canonical_sid...]`

This is built by scanning only active canonical restricted signatures (`RestrictCanon`), not rows.

## How Restriction Is Applied
### 1) No more `RestrictTerm` bitset intersection in witness init (hot path)
In `refine_witness_active_sigs(...)`, witness `ActiveSig` is no longer intersected with a projected term bitset at initialization.

Code path:
- `custom_filter/policy.cpp:5540` (`refine_witness_active_sigs`)

### 2) Pair-bundle pruning filters restricted source signatures via key index
In `prune_pair_bundle_one_direction(...)`, if the source table is dependency-restricted:
- fetch/build `RestrictKeyIndex` for the source key schema
- for comparator bundles: only include source signatures supported by restricted canonical signatures for that key and source-side comparator columns
- for join-only bundles: current implementation avoids RID dependency work but still relies on bundle-time key checks / prefiltering

Code path:
- `custom_filter/policy.cpp:5224` (`prune_pair_bundle_one_direction`)
- key index build/fetch: `custom_filter/policy.cpp:4356`, `custom_filter/policy.cpp:4400`

### 3) Predicate-only witness path uses canonical restricted signatures directly
Avoids `RestrictTerm`/canon->term map on predicate-only witness checks:
- `custom_filter/policy.cpp:6813` (`table_has_predicate_witness`)

## Counters Added
- `restrict_key_index_build_ms`
- `restrict_key_index_entries`
- `restrict_key_index_bytes`
- `restrict_key_prune_ms`

Existing counters retained for comparison:
- `canon_term_map_build_ms`
- `restrict_term_apply_ms`
- `restrict_term_sigs_dropped`
- `proj_rid_iters_dependency`

## Current Outcome
### Architectural / correctness-facing
- `proj_rid_iters_dependency = 0` preserved
- Stage 8C row inflation remains fixed (rows match Stage 8B in drona layer-probe window)
- Stage 8C.1 `RestrictTerm` image work is removed from the hot dependency path (`restrict_term_*` drops to zero)

### Performance (current implementation)
- `canon_term_map_build_ms` drops sharply on q1/q3/q6 (about 3.5s -> ~0.53s)
- but end-to-end `project_ms` and `policy_total_ms` are still worse than Stage 8C.1 / Stage 8B

This means the current restriction-key integration removes one expensive cost but does not yet preserve enough pruning efficiency; repeated key-based filtering inside pair-bundle propagation is now the dominant added overhead.

## Next Correction Path (Stage 8C.2.1)
To make this approach viable:
1. Build per-key comparator summaries (min/max ranks, equality token sets) instead of storing / scanning canonical sid vectors where possible.
2. Apply a deduplicated one-time key prefilter per restricted table keyed by unique key schemas (avoid repeated full ActiveSig scans per bundle).
3. Reuse per-term key extraction caches for signatures to avoid repeated `signature_extract_cols_tokens(...)` allocations and hashing inside pair-bundle loops.
