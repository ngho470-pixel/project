# Stage 8C: Signature-Only Dependency Chaining (Strict Experimental Mode)

## Goal
Remove RID-based dependency restriction (`restrict_bits`) from the exact policy-evaluation path. Intermediate policy targets are now represented as query-local signature-feasibility sets (`restrict_active_sig`) rather than RID bitmaps.

This targets the remaining projection bottleneck where RID iteration was still dominating `project_ms` despite Stage 8B dense `block_words`.

## Theory (Exact, Unchanged Semantics)
For each policy target table `U` processed in dependency order, we compute:
- `AllowSig(U)`: allowed canonical signature IDs (query-local, canonical schema for `U`)
- `AllowCTID(U)`: CTID/block bitmap only for executor enforcement when `U` is scanned

Downstream targets use only `AllowSig(U)` for witness restriction.

## Canonical Restrict State
Added query-local restrict state per dependency target:
- `RestrictSigState { schema_cols, active_sig }`
- `schema_cols`: canonical schema (currently `table_needed_signature_schema(ti)`)
- `active_sig`: union/intersection-composed signature bitset for the target’s final policy formula

Key implementation points:
- `custom_filter/policy.cpp:1637` `RestrictSigState`
- `custom_filter/policy.cpp:7403` `build_target_allow_list(...)` now optionally returns `RestrictSigState`
- `custom_filter/policy.cpp:7806` `policy_run(...)` now carries `restrict_sigs` instead of `rid_bits_by_table` / `restrict_bits`

## How RestrictSig Is Built
`build_target_allow_list(...)` now accumulates a canonical signature bitset in parallel with `block_words`:
- permissive roots: OR-union of formula signature bitsets
- restrictive roots: AND with per-root signature bitsets
- final signature bitset exactly mirrors the existing `block_words` Boolean composition

Implementation points:
- `custom_filter/policy.cpp:7178` `eval_formula_root_words(...)` now optionally returns formula-level signature union (`out_formula_sig_bits`)
- `custom_filter/policy.cpp:7493`, `:7550`, `:7581` root eval call sites in `build_target_allow_list(...)`

## Downstream Restriction Application (No RID Mask)
Witness/table initialization now starts from signature restrictions:
- `custom_filter/policy.cpp:4499` `init_witness_active_sig_for_table(...)` takes `const TokenBitset *restrict_active_sig`
- `custom_filter/policy.cpp:4906` `refine_witness_active_sigs(...)` accepts `restrict_sigs` and initializes `ActiveSig` from them
- Restricted tables are initialized with canonical signature caches (matching `RestrictSigState.schema_cols`)

Predicate-only witness tables (no class groups) now also honor signature restrictions:
- `custom_filter/policy.cpp:6425` `table_has_predicate_witness(...)` uses signature-level predicate checks when `restrict_sigs` contains the table

## Strict-Mode Guardrail (Fail-Loud)
Legacy RID-based dependency restriction is forbidden in strict mode.
A fail-loud guard is added in projection:
- `custom_filter/policy.cpp:5326` errors if `restrict_bits` reaches projection in strict mode

## Counters Added
To prove the RID dependency path is removed and attribute the new path:
- `proj_rid_iters_scan_enforcement`
- `proj_rid_iters_dependency` (should be `0` after Stage 8C)
- `restrict_sig_tables`
- `restrict_sig_schema_cols_total`
- `restrict_sig_bytes_total`
- `restrict_sig_apply_ms`

Emitted in:
- `custom_filter/policy.cpp:6635` (`policy_profile_query`)
- `custom_filter/custom_filter.c:1793` (`policy_profile`)
- parsed by `fast_sweep_profile_60s.py` (`PROFILE_COLUMNS` / `LAYER_PROBE_COLUMNS`)

## Current Result (What Stage 8C Achieved)
- `proj_rid_iters_dependency` is now `0` on the drona `tpch1` cross-table window (11–20), confirming RID-based dependency chaining is removed from the exact path.
- Correctness remains intact on Stage 9 col-op-col tests (`tpch0_1` local and `tpch1` drona, including policies 27/29).

## Important Performance Outcome
Stage 8C removes the dependency RID loop, but on the tested cross-table window it regressed `project_ms`/`policy_total_ms` vs Stage 8B.
This indicates the dominant cost moved to signature-level cardinality / projection work (not dependency RID plumbing anymore).

This is still a useful diagnostic milestone: the new split counters prove the previous bottleneck is gone.
