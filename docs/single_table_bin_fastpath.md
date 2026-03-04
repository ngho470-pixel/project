# Single-Table Bin Fast Path

This documents the intended strict-mode fast path for single-table policies.

## Target Behavior

If a term only references one table (no witness joins), evaluation should be bin-only:

- unary atoms compile to token/rank bin sets,
- `AND` -> intersection,
- `OR` -> union,
- short-circuit:
  - `AND` with empty => empty,
  - `OR` with universal => universal.

No heap row scan should be used for policy evaluation in this path.

## Runtime Evidence Counters

`policy_profile_query` / gate CSV fields used to confirm fast path:

- `single_table_bin_fastpath_used`
- `bin_ops_total`
- `bins_touched_total`
- `bin_rids_scanned_total`
- `allow_cache_hit` / `allow_cache_miss` / `allow_cache_build_ms`

## Cache Scope

Allow-set cache key must include at least:

- DB identity,
- target table OID,
- policy-set fingerprint,
- strict/runtime flags impacting semantics.

This ensures reuse across multiple queries in the same gate run without cross-policy contamination.

