# Policy-First V2.2: Hub-Token Bitsets + Bin Stamping (Single-Hub Terms)

## Scope
This stage adds a policy-first evaluation path that avoids signature-mask OR projection loops for a restricted term shape:
- single-hub conjunction terms only (one join domain across all cross-table atoms)
- target is hub-only (no target-local predicates in the term)
- witness-local predicates are supported via row stamping (`col op const` only in the current implementation subset)
- no chains, no multi-hub terms, no dependency-restricted witnesses

Unsupported terms fail-loud when `custom_filter.policy_first_v2_force=on`.

## Core Idea
For an eligible conjunction term and hub domain `D*`:
1. Build a token bitset `Tok(τ)` over hub tokens.
2. Intersect token-presence bitsets for all hub-participating tables (join existence).
3. For each witness table with local predicates, scan rows once and stamp hub tokens that satisfy the local predicate conjunction.
4. Intersect into `Tok(τ)`.
5. Project allowed hub tokens to target rows using CSR bins `Bin(T,D*,t)` and stamp CTIDs directly.

SAT is still used to enumerate OR-selector conjunction terms. PF-V2.2 replaces the term projection realization only for eligible terms.

## Why This Differs From Previous Policy-First
Previous path:
- build/propagate signature sets, then OR per-signature CTID masks across models/terms
- hot cost dominated by signature-mask OR loops

PF-V2.2 path:
- compute allowed hub token bitsets (`Tok(τ)`) via existence stamping
- project token -> RID using CSR bin index
- stamp CTIDs directly

This keeps policy reasoning at token/bin granularity and avoids per-signature CTID mask OR work for eligible terms.

## Artifact Dependency
PF-V2.2 depends on PF-V2.1 bin CSR artifacts:
- `bin/<table>/domain_<id>.off`
- `bin/<table>/domain_<id>.rids`
- `meta/bin_index`

## Runtime Controls
- `custom_filter.policy_first_v2=on`
- `custom_filter.policy_first_v2_force=on` (strict fail-loud on unsupported terms)

## Code Mapping (current subset)
- PF2 GUCs: `custom_filter/custom_filter.c`
- PF2 counters + logging: `custom_filter/policy.cpp` (`BuildProfile`, `policy_profile_query`)
- PF2 helpers:
  - `pf2_build_present_tokens_for_table(...)`
  - `eval_term_conjunction_pf2_single_hub(...)`
- PF2 hook into term evaluation:
  - `eval_term_conjunction_words(...)`

## Current Limitations (intentional for V2.2)
- no chain composition
- no multi-hub terms
- no dependency-restricted witness tables (`restrict_sigs`)
- no same-table `col op col` witness-local stamping yet
- no cross-table `col op col` comparators in PF2 path yet

The correctness/perf gates for this stage use a dedicated PF-V2.2-only policy set (`P_A`, `P_B`, `P_C`) chosen to stay within the supported subset.
