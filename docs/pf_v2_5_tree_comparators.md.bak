# PF-V2.5 Tree Comparators (Acyclic PF2, Strict Exact)

## Scope
PF-V2.5 extends PF-V2.4 tree/forest token propagation to support a strict exact subset of cross-table `col op col` comparators on PF-supported terms, while keeping:
- SAT selectors only for OR-branch enumeration
- bin/CSR token->RID artifacts for propagation and projection
- no signature-mask OR loops (`proj_sig_count=0`, `proj_mask_or_ops=0`, `proj_rid_iters=0` on PF cases)
- no ActiveSig propagation and no DFS/backtracking

## Supported in this implementation
- Acyclic PF factor graph terms (PF-V2.4 tree path)
- Cross-table comparators where:
  - one comparator endpoint is the target table
  - comparator separator key arity is 1 (single key domain on the unique table-path)
  - operator in `{=,<,<=,>,>=}`
- Local (same-table) comparators remain handled as PF local row predicates during stamping/projection

## Unsupported (fail-loud under `policy_first_v2_force=on`)
- Cyclic PF factor graph terms
- Cross-table `!=`
- Cross-table comparator separator key arity `> 1` (arity-2 planned for follow-up)
- Cross-table comparators whose endpoints are both non-target witness tables
- Multi-hub target enforcement (PF-V2.4 limitation retained)

## Comparator Summary (keyed by separator token)
For a supported comparator between target `U` and witness `V` keyed by separator domain `K` (arity 1), PF-V2.5 builds a query-local summary over `V`:
- `present[k]`: at least one witness row exists for key token `k`
- `min_rank[k]`, `max_rank[k]` for ordered comparators
- `eq_set[k]` for equality comparators

Witness rows contributing to the summary must satisfy:
- local predicates on `V`
- same-table local comparators on `V`
- all final PF-V2.4 domain->table membership messages on incident join domains

This preserves existential witness semantics without building signatures or joins.

## How comparator checks are applied
PF-V2.5 keeps PF-V2.4 tree propagation unchanged and applies supported comparator checks during target bin projection:
1. PF-V2.4 computes allowed target-hub tokens by tree message propagation.
2. PF-V2.5 projects candidate target rows via target CSR bins.
3. For each candidate row, PF-V2.5 checks comparator feasibility against keyed witness summaries.
4. Passing rows are stamped to CTID `block_words`.

This remains policy-first and bin-based.

## Code Mapping
- Comparator planning in PF tree detector: `custom_filter/policy.cpp` (`pf2_tree_detect_pattern(...)`)
- Keyed comparator summary build (arity 1): `custom_filter/policy.cpp` (`pf2_tree_build_cmp_summary_key1(...)`)
- Target-row comparator check against summary: `custom_filter/policy.cpp` (`pf2_cmp_summary_accept_target_row(...)`)
- PF tree evaluator integration: `custom_filter/policy.cpp` (`eval_term_conjunction_pf2_tree(...)`)

## Correctness sketch
For supported terms, a target row is accepted iff:
- it is in a target-hub token allowed by exact PF tree propagation (existential join/local witness semantics over the acyclic graph), and
- for each supported cross-table comparator, there exists a witness row under the separator key satisfying local/tree constraints and comparator relation to the target row value.

The keyed summaries encode exactly the existential witness facts needed for these comparator checks.
