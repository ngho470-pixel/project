# PF-V2.7: Cyclic PF (Policy29-Shape Rectangle) Exact Path

## Scope
PF-V2.7 adds an exact PF path for a **cyclic rectangle** factor graph:

- exactly 2 tables: target `T` and witness `W`
- exactly 2 join domains `(d0, d1)` connecting `T <-> W`
- optional local predicates / same-table comparators on `T` and `W`
- exactly one cross-table comparator between `T` and `W`
- comparator operator in `{=,<,<=,>,>=}` (`!=` fail-loud)

This covers the policy29 shape:

- `lineitem.l_partkey = partsupp.ps_partkey`
- `lineitem.l_suppkey = partsupp.ps_suppkey`
- `lineitem.l_quantity <= partsupp.ps_availqty`

## Non-goals (still fail-loud in force mode)
- general cyclic PF graphs
- cross-table `!=`
- multiple cross-table comparators in one cyclic term
- comparator endpoints not exactly target/witness
- signature engine fallback in `policy_first_v2_force=on`

## Exact Algorithm
1. Detect the cycle rectangle term shape (2 tables, 2 join domains, target-endpoint comparator).
2. Build a query-local witness keyed summary over `(d0,d1)` by scanning witness rows once:
   - enforce witness local predicates/same-table comparators
   - record `present[(k0,k1)]`
   - record comparator summary (`min/max rank` or `eqset`) for witness comparator column
3. Derive allowed target hub tokens (projection-driving domain) from summary key pairs.
4. Project target rows via target CSR bins on the hub domain:
   - for each target row in selected bins:
     - enforce target local predicates/same-table comparators
     - enforce key-pair presence + cross-table comparator via keyed summary
     - stamp CTID into dense `block_words`

This stays in the PF regime:
- token/bin/CSR as primitives
- no signature-mask OR loops
- no ActiveSig
- no DFS/backtracking
- no join materialization

## Code Mapping
- Cycle-rectangle detector: `custom_filter/policy.cpp` `pf2_cycle_rect_detect_pattern(...)`
- Direct key2 witness summary build: `custom_filter/policy.cpp` `pf2_cycle_build_cmp_summary_key2_direct(...)`
- Cycle term evaluator: `custom_filter/policy.cpp` `eval_term_conjunction_pf2_cycle_rect(...)`
- PF dispatch integration: `custom_filter/policy.cpp` term-eval dispatch before PF tree path

## Correctness Statement (supported subset)
For supported PF-V2.7 terms, a target row is accepted iff:
- target local atoms hold on the row, and
- there exists at least one witness row with the same `(d0,d1)` key pair satisfying witness local atoms, and
- the cross-table comparator is satisfied using the witness summary for that key pair.

This is exact existential witness semantics for the 2-table/2-domain cycle-rectangle subset.
