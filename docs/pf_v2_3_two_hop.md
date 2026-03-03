# PF-V2.3 Two-Hop (Policy-First V2, Exact)

## Goal
Extend PF-V2.2 (single-hub token stamping) to exact 2-hop chain terms while preserving the same evaluation model:

- SAT only chooses OR branches (selector models)
- term feasibility is computed over token classes / bins
- target projection is token->RID CSR bin projection
- no signature-mask OR loops
- no ActiveSig/global propagation
- no DFS/backtracking

## Supported Term Shape (PF-V2.3)
PF-V2.3 supports a strict 2-hop chain anchored at the target:

- `T --H1--> A --H2--> B`
- exactly two equijoin edges (`=` col-col) in the term join graph
- target `T` participates only on `H1`
- leaf witness `B` participates only on `H2`
- middle witness `A` participates only on `H1` and `H2`
- local predicates/comparators may exist on `A` and/or `B`
- target-local predicates/comparators are not supported in PF-V2.3 (fail-loud when forced)
- cross-table comparators are not supported in PF-V2.3 (fail-loud when forced)

Examples covered:

- `lineitem -> orders -> customer`
- `orders -> customer -> nation`
- `supplier -> nation -> region`

## Exact Algorithm (Per SAT Term)
Given term `tau` with chain `T --H1--> A --H2--> B`:

1. Build `Tok_T_present(H1)` from target bin CSR presence (`bin_off[t+1] > bin_off[t]`).
2. Build `Tok_B(H2)` by scanning `B` rows once:
   - require row's `H2` token to be valid
   - apply `B` local predicates/comparators
   - stamp `H2` token bit on success
3. Build `Tok_A(H1)` by scanning `A` rows once:
   - require row's `H1` and `H2` tokens valid
   - require `Tok_T_present(H1)` and `Tok_B(H2)` bits set
   - apply `A` local predicates/comparators
   - stamp `H1` token bit on success
4. `Tok_allow(tau) = Tok_A(H1) AND Tok_T_present(H1)`
5. Project target rows via target CSR bins:
   - for each allowed `h in Tok_allow(tau)`, iterate `Bin(T,H1,h)` RIDs
   - map RID -> CTID using `T_ctid`
   - set bits in dense `block_words`

This is exact existential composition:

- `h` is allowed iff there exists an `A` row under `H1=h` and a linked `B` row under `H2` satisfying local predicates.

## SAT Integration
PF-V2.3 reuses the existing SAT/Tseitin selector enumeration.

For each SAT model:
- extract conjunction term
- if PF-V2.2 single-hub shape -> evaluate via PF-V2.2
- else if PF-V2.3 two-hop shape -> evaluate via PF-V2.3
- else unsupported

The resulting term row-allow is OR-unioned across models by stamping into the target `block_words`.

## Unsupported Shapes (Fail-Loud in `policy_first_v2_force=on`)
- 3+ hop chains
- multi-hub / branching terms
- cross-table comparators
- cyclic join graph
- target-local predicates in PF-V2.3 path

## Implementation Mapping
- Bin CSR loader / slices:
  - `custom_filter/policy.cpp` `get_or_build_bin_index_cache_entry(...)`
  - `custom_filter/policy.cpp` `get_bin_slice(...)`
- Two-hop pattern detection:
  - `custom_filter/policy.cpp` `pf2_detect_two_hop_pattern(...)`
- PF-V2.3 evaluator:
  - `custom_filter/policy.cpp` `eval_term_conjunction_pf2_two_hop(...)`
- PF2 dispatch hook:
  - `custom_filter/policy.cpp` `eval_term_conjunction_words(...)`

## Profiling Counters (PF-V2.3)
Added / used:

- `pf2_terms_total`
- `pf2_terms_supported`
- `pf2_terms_single_hub`
- `pf2_terms_two_hop`
- `pf2_terms_failed_shape`
- `pf2_stamp_rows_scanned_A`
- `pf2_stamp_rows_scanned_B`
- `pf2_stamp_ms_A`
- `pf2_stamp_ms_B`
- `pf2_tok_compose_ms`
- existing PF2 counters (`pf2_stamp_ms`, `pf2_project_ms`, `pf2_total_ms`, etc.)

PF2 invariant in supported terms:

- `proj_sig_count = 0`
- `proj_mask_or_ops = 0`
- `proj_rid_iters = 0`
