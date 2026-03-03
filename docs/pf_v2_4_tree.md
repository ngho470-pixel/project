# PF-V2.4 Tree (Acyclic Factor-Graph Token Propagation)

## Goal
Generalize PF-V2.2 (single-hub) and PF-V2.3 (2-hop chain) to exact evaluation of any acyclic join term (tree/forest) using token/bin propagation, while keeping SAT only for OR-selector model enumeration and target projection via CSR bins.

## Core Model
For one conjunction term, build a bipartite factor graph:
- variable nodes: join domain IDs used by equijoin atoms
- factor nodes: tables in the term
- edge `(table, domain)` if the table participates in that join domain in the term

PF-V2.4 supports only acyclic join factor graphs. Cycles fail-loud in `strict_mode=on` with `policy_first_v2_force=on`.

## Messages (Token Bitsets)
For each domain `d`, messages are token bitsets over `Tok(d)`:
- domain->table: `m_{d->T}`
- table->domain: `m_{T->d}`

Tree equations:
- `m_{d->T} = ∩_{T' in N(d) \ {T}} m_{T'->d}`
- `t in m_{T->d}` iff there exists a row `r` in `T` with token(r,d)=t such that:
  - row satisfies all local atoms on `T` (`col op const`, same-table `col op col`)
  - for every other incident domain `d'`, `token(r,d') in m_{d'->T}`

A root domain is chosen at the target's single join domain (single-hub target enforcement requirement in PF-V2.4). For disconnected forest components not containing the target, PF-V2.4 checks component satisfiability (`A_root != empty`) but does not project rows.

## Table Update Implementation (CSR/Bin-Driven)
A table update scans rows through a driving domain bin index:
- choose a safe driving domain (prefer smallest incoming message set)
- iterate tokens in the driving incoming set (or full bin presence for leaf-upward updates)
- iterate rows via `get_bin_slice(table, domain, token)`
- check local row atoms and incoming domain-message membership for all incident domains
- stamp supported tokens into outgoing table->domain message bitsets

This avoids signature DP, signature-mask OR loops, and join output materialization.

## SAT Role
Unchanged and narrow:
- SAT/Tseitin + OR selectors enumerate exact conjunction terms (models)
- PF-V2.4 evaluates each term exactly via tree propagation
- model results are OR-unioned into final target `block_words` via target-bin projection

## Target Projection
After propagation, PF-V2.4 gets allowed tokens on the target root domain `d_h`.
Projection is:
- iterate allowed tokens `t` in `A_{d_h}`
- iterate target RID slice `Bin(T, d_h, t)` via CSR
- apply target local row atoms (exact row-level filter within allowed token bin)
- stamp RID->CTID into dense `block_words`

No signature-mask projection is used in PF-V2.4 code paths.

## Supported Shapes (PF-V2.4)
- Any acyclic join factor graph (tree/forest) with equijoins only
- Local unary predicates on any table (`col op const`)
- Same-table local comparators (`col op col`) evaluated at row time
- Multiple local predicates across tables

## Fail-Loud (PF-V2.4 Force Mode)
PF-V2.4 fails loud on:
- cyclic join factor graphs
- cross-table comparators (`col op col` across tables)
- multi-hub target enforcement (target incident to >1 join domain) in current implementation

## Code Mapping
- factor/tree detection: `custom_filter/policy.cpp` (`pf2_tree_detect_pattern`)
- generic tree evaluator: `custom_filter/policy.cpp` (`eval_term_conjunction_pf2_tree`)
- generic table update/message emit: `custom_filter/policy.cpp` (`pf2_tree_emit_table_messages`)
- domain message intersection: `custom_filter/policy.cpp` (`pf2_tree_compute_domain_to_table_message`)
- dispatch integration: PF2 single-hub -> two-hop -> tree in `eval_term_conjunction_words(...)`

## Correctness Statement
For supported acyclic terms, PF-V2.4 implements exact existential witness semantics over the join tree using token-set message propagation and row-validity checks under local atoms. Final row visibility remains exact because target rows are projected only from allowed root-domain tokens and rechecked for target-local atoms before CTID stamping.
