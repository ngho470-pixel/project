# Stage 8C.1: Canonical-to-Term Restrict Map (Exact Signature Dependency Chaining)

## Goal
Keep the Stage 8C architectural correction (`proj_rid_iters_dependency = 0`, no RID-based dependency chaining) while restoring lean term-schema evaluation cost.

Stage 8C regressed because dependency restriction was applied by initializing witness tables on a canonical (superset) schema. Stage 8C.1 fixes this by projecting canonical allowed signatures onto each term schema via an exact existential image.

## Exact Semantics
For dependency table `U`:

- Canonical query-local schema: `S_canon(U)`
- Canonical allowed signatures: `RestrictCanon(U) ⊆ SigIDs(S_canon(U))`

For a term `t`, the term schema is `S_term(U,t) ⊆ S_canon(U)`.

Restriction applied to term evaluation is:

- `RestrictTerm(U,t) = { sid_term | ∃ sid_canon ∈ RestrictCanon(U): π(tokens(sid_canon)) = tokens(sid_term) }`
- `ActiveSig_term(U) := ActiveSig_term(U) ∩ RestrictTerm(U,t)`

This is exact under existential witness semantics and avoids forcing term evaluation onto the canonical schema.

## Query-Local Cache (Stage 8C.1)
Stage 8C.1 adds a query-local canonical→term mapping cache:

- `CanonTermMapCacheEntry`: `custom_filter/policy.cpp:1464`
- `RestrictSigState` (now includes `term_restrict_cache`): `custom_filter/policy.cpp:1660`

### Cache keys
- table name
- canonical schema key
- term schema key

### Cached values
- `canon_to_term_sid[sid_canon] -> sid_term` mapping
- projected term restriction bitset (`RestrictTerm`) cached per `(table, canon_schema, term_schema)`

## Implementation Flow
### 1) Build / fetch canon→term map
- `get_or_build_canon_to_term_map_cache_entry(...)`: `custom_filter/policy.cpp:4173`

Builds an exact map from canonical signature IDs to term signature IDs using signature-cache token tuples (no row scans).

### 2) Project canonical restriction onto term schema
- `get_or_build_restrict_term_bitset(...)`: `custom_filter/policy.cpp:4208`

This computes `RestrictTerm(U,t)` once per query per schema pair and caches it in `RestrictSigState.term_restrict_cache`.

### 3) Apply restriction to witness ActiveSig on term schema (not canonical)
- `refine_witness_active_sigs(...)`: `custom_filter/policy.cpp:5194`
- restriction application call path (term schema cache + AND): `custom_filter/policy.cpp:5251`

Witness `ActiveSig` is initialized on the clause/term schema and immediately intersected with the projected term restriction bitset.

### 4) Predicate-only witness checks honor the same restriction
- `table_has_predicate_witness(...)`: `custom_filter/policy.cpp:6727`
- projected restriction use: `custom_filter/policy.cpp:6764`

This removes the Stage 8C canonical-schema shortcut from predicate-only witness paths too.

## Formula-Level Canonical Signature Accumulation (Exact)
Stage 8C.1 also fixes formula-level canonical signature accumulation to avoid Stage 8C over-broad fills:

- `lift_term_active_to_canonical(...)`: `custom_filter/policy.cpp:4285`
- `eval_term_conjunction_words(...)` (term returns canonical sig bits): `custom_filter/policy.cpp:7225`
- `eval_formula_root_words(...)` (OR/AND over exact canonical sig bitsets): `custom_filter/policy.cpp:7523`

This restores exact downstream restriction composition while keeping signature-only dependency chaining.

## Counters Added (Attribution)
Engine and harness now expose:

- `canon_term_map_cache_hits`
- `canon_term_map_cache_misses`
- `canon_term_map_build_ms`
- `canon_term_map_bytes`
- `restrict_term_apply_ms`
- `restrict_term_sigs_kept`
- `restrict_term_sigs_dropped`

Counter emission / parsing:
- engine profile log fields: `custom_filter/policy.cpp:6937`
- extension aggregation/logging: `custom_filter/custom_filter.c:1807`, `custom_filter/custom_filter.c:2620`
- harness parsing: `fast_sweep_profile_60s.py:195`, `fast_sweep_profile_60s.py:3026`

## Outcome (Stage 8C.1)
- Preserves Stage 8C architectural win: `proj_rid_iters_dependency = 0`
- Fixes Stage 8C row inflation / over-broad restriction (rows return to Stage 8B values)
- Does **not** yet recover `project_ms` on the drona `tpch1` cross-table window (`11..20`, `K=10`, `q1/q3/q6`)

This narrows the remaining bottleneck to signature-level projection/propagation cost, not RID dependency chaining.
