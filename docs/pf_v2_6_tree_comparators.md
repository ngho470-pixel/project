# PF-V2.6 Tree Comparators (Acyclic PF2, Strict Exact, Key Arity 1-2)

## Scope
PF-V2.6 extends PF-V2.5 comparator support on the PF-V2.4 tree/forest path to support a strict exact subset of **separator key arity 2** cross-table comparators, while preserving:
- SAT selectors only for OR-branch enumeration
- bin/CSR token->RID artifacts for propagation and projection
- no signature-mask OR loops (`proj_sig_count=0`, `proj_mask_or_ops=0`, `proj_rid_iters=0` on PF cases)
- no ActiveSig propagation and no DFS/backtracking

## Supported in this implementation
- Acyclic PF factor graph terms (PF-V2.4 tree path)
- Cross-table comparators where:
  - one endpoint is the target table
  - operator in `{=,<,<=,>,>=}`
  - separator key arity is `1` or `2`
- PF-V2.6 key-arity 2 support is exact for the implemented subset:
  - target endpoint provides the full separator key tuple
  - witness endpoint provides comparator value and the path-near separator key
  - an intermediate bridge table on the unique path composes the endpoint witness summary into a `(k0,k1)` keyed summary

## Unsupported (fail-loud under `policy_first_v2_force=on`)
- Cyclic PF factor graph terms
- Cross-table `!=`
- Cross-table comparator separator key arity `> 2`
- Cross-table comparators whose endpoints are both non-target witness tables
- PF shapes unsupported by PF-V2.4 tree detection

## Comparator Summary Model

### Key arity 1 (PF-V2.5)
Same as PF-V2.5:
- witness summary keyed by separator token `k`
- `present[k]`
- `min/max rank[k]` for ordered comparators
- `eq_set[k]` for equality comparators

### Key arity 2 (PF-V2.6)
For comparator between target `U` and witness `V` with separator key tuple `(k0, k1)` on the unique PF tree path:
1. Build endpoint witness summary on `V` keyed by the path-near key `k1` (exact PF membership + local atoms).
2. Scan the unique bridge table on the path (carrying both separator domains) and compose a keyed summary over `(k0,k1)`:
   - row must satisfy bridge-local atoms
   - row must satisfy PF domain->table membership on all bridge incident domains
   - `k1` must be present in the endpoint witness summary
   - update `(k0,k1)` summary with witness comparator facts (min/max/eq-set)

This preserves existential witness semantics without materializing joins or signatures.

## How comparator checks are applied
PF-V2.6 keeps PF-V2.4 tree propagation unchanged and applies comparator checks during target bin projection:
1. PF-V2.4 computes allowed target-hub tokens by exact tree propagation.
2. PF projects candidate target rows via target CSR bins.
3. PF-V2.6 checks each supported cross-table comparator against keyed summaries (`k` or `(k0,k1)`).
4. Passing rows are stamped to CTID `block_words`.

## Code Mapping
- Comparator planning in PF tree detector: `custom_filter/policy.cpp` (`pf2_tree_detect_pattern(...)`)
- Keyed comparator summary build (arity 1): `custom_filter/policy.cpp` (`pf2_tree_build_cmp_summary_key1(...)`)
- Keyed comparator summary build (arity 2): `custom_filter/policy.cpp` (`pf2_tree_build_cmp_summary_key2(...)`)
- Target-row comparator check against summary: `custom_filter/policy.cpp` (`pf2_cmp_summary_accept_target_row(...)`)
- PF tree evaluator integration: `custom_filter/policy.cpp` (`eval_term_conjunction_pf2_tree(...)`)

## Correctness sketch
For supported PF-V2.6 terms, a target row is accepted iff:
- it is reachable under exact PF tree token propagation (existential join/local witness semantics over the acyclic graph), and
- for each supported comparator, the keyed summary proves existence of a witness assignment under the same PF membership/local-atom constraints satisfying the comparator relation to the target row value.

No signature-based projection or row-pair join materialization is used.
