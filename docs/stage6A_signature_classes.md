# Stage 6A Signature-Class Evaluation

## Scope
Stage 6A changes only intra-query term evaluation in `custom_filter/policy.cpp`.

Unchanged:
- policy language and atom semantics,
- SAT/hybrid model enumeration and selector behavior,
- artifact schema (`dict/domain`, `rank/domain`, `*_ctid`),
- permissive/restrictive composition.

## Formal objects implemented

For each clause-table `U` in a conjunction term:
- signature schema `S_U`: all table columns referenced by that term on `U` (join-group columns + local predicate columns),
- signature id `sid_U(rid)`: id of token tuple over `S_U`,
- signature classes `C_{U,k} = {rid | sid_U(rid)=k}`.

Runtime state:
- `ActiveSig[U]` represented as sid bitsets per term-model,
- token supports still represented by `Allowed[...]` bitsets,
- projection for target table is union of rowlists of active signature ids.

## Implementation mapping

- Signature cache entry:
  - `SignatureCacheEntry` in `custom_filter/policy.cpp`.
- Per-table term schema:
  - `clause_table_signature_schema(...)`.
- Query-local cache key:
  - `signature_cache_key(...)`.
- Build/cache signatures once per `(table, schema)`:
  - `build_signature_cache_entry(...)`
  - `get_or_build_signature_cache_entry(...)`.
- Signature-level row predicate / join-group / comparator checks:
  - `signature_matches_clause_table(...)`.
- Class-based projection:
  - `project_active_signatures_to_rows(...)`.
- Target projection path switched from full rid scan to signature projection:
  - `eval_term_conjunction_bits(...)`.

## Counters added

Added to policy profile:
- `signature_cache_hits`
- `signature_cache_misses`
- `term_code_scans`
- `target_full_row_scans`

Plumbed through:
- `PolicyRunProfileC` in `custom_filter/policy.cpp` and `custom_filter/custom_filter.c`,
- `policy_profile_query` and `policy_profile` NOTICE output.

Interpretation:
- `term_code_scans`: number of signature-cache builds (one per cache miss),
- `target_full_row_scans`: number of full target rid scans in term projection path (Stage 6A target is 0 in steady state).

## Validation

Results in:
- `logs/stage6A_correctness.csv`
- `logs/stage6A_correctness.md`

Stage6A-specific micro case (`signature_cache_multi_model_or`) confirms:
- multi-model OR union remains correct vs RLS hash/count,
- signature cache is reused inside a single query (`hits>=1`, `misses>=1`),
- target full-row scan count is zero (`target_full_row_scans=0`).

