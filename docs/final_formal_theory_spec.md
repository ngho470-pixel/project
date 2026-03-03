# Final Formal Theory Spec

## 0. System Goal

We enforce row-level authorization inside PostgreSQL without query rewriting. For each scanned base relation `T`, we compute an exact allowed tuple set and enforce it at scan time via CTID membership.

Design principle:

- Evaluate authorization using token domains + signature classes + SAT (for OR choices).
- Never materialize join outputs.

## 1. Policy Language (Strict Scope)

A policy for a target table `T` is a Boolean formula built from atoms using `AND` / `OR`.

### 1.1 Atoms (The Only Ones Allowed)

- Column-constant: `c theta k`
- Column-column: `c1 theta c2`

Where:

- `c`, `c1`, `c2` are fully-qualified column references `table.col`
- `k` is a typed constant
- `theta in {=, !=, <, <=, >, >=}`

Not allowed (strict scope):

- `IN`
- `LIKE`
- `BETWEEN` as syntax (must be expanded into comparisons)
- UDFs
- `NOT`

### 1.2 NULL Semantics

If either operand is `NULL`, the comparison evaluates `UNKNOWN` and is treated as false for visibility (SQL `WHERE` semantics).

### 1.3 Permissive / Restrictive Composition

For a target `T`, active policies partition into:

- permissive set `P_T`
- restrictive set `R_T`

Effective formula:

- `Perm(T) = OR_{p in P_T} p`
- `Rest(T) = AND_{r in R_T} r`
- `Final(T) = Perm(T) AND Rest(T)`

If `P_T` is empty, result is deny-all for `T`.

## 2. Artifacts (Build Phase, Policy-Agnostic)

Artifacts are built for the active policy set `Pi` and dataset instance `D`.

### 2.1 Policy-Scoped Columns

For each table `T`:

- `Cols(T) = { columns of T referenced by any atom in Pi }`

Only `Cols(T)` appears in code artifacts.

### 2.2 Comparable Domains (Stage 9, Option A)

Each column `table.col` is assigned a `domain_id`. A domain is a set of columns sharing one token universe.

#### 2.2.1 Type Classes (Strict)

Each column belongs to exactly one type class:

- `NUMERIC`: `int2/int4/int8/numeric/decimal`
- `DATE`: `date` (optionally timestamp types only if explicitly included)
- `TEXT`: `text/varchar/bpchar`

#### 2.2.2 Domain Graph

Let `V` be all policy-referenced columns (including columns used in col-const atoms).

Add an undirected edge between `c1` and `c2` for every `col theta col` atom in `Pi` iff `type_class(c1) == type_class(c2)`.

Otherwise, compilation/build fails in strict mode.

Domains are connected components of this graph.

#### 2.2.3 Deterministic Domain IDs

For each domain component `D`, define:

- `canon(D) =` lexicographically smallest member `table.col`

Sort components by `canon(D)` and assign `domain_id = 0..k-1`.

Artifacts:

- `meta/col_domain`: `table.col -> domain_id`
- `meta/domains` or `meta/join_classes`: membership listing per `domain_id` (semantics is domains)

### 2.3 Domain Dictionaries

For each domain `D`:

- Build `Values(D)` = union of distinct non-NULL values appearing in any member column.
- Construct `dict/domain/<id>` mapping `value -> token`.

Domain token invariant:

For any `c1, c2 in D` and rows `r1, r2`:

- `tok(r1,c1) == tok(r2,c2) <=> val(r1,c1) == val(r2,c2)`

### 2.4 Rank Metadata for Ordered Comparisons

If any atom in `Pi` uses `<, <=, >, >=` on a domain `D`, create:

- `rank/domain/<id>` mapping `token -> rank`

Rank must reflect domain ordering:

- `NUMERIC`: numeric order
- `DATE`: chronological order
- `TEXT`: deterministic lexicographic order (collation/comparator must be specified and match evaluation assumptions)

### 2.5 Code Artifacts

For each table `T`:

- `meta/cols/<T>`: list of `Cols(T)` in stable order
- `T_code_base` (`CB04/CC04`): bitpacked per-column token arrays for `Cols(T)` only
- `T_ctid`: RID -> CTID map (`RID` = artifact row index)

## 3. Runtime Policy Evaluation (Per Query Execution)

Given a query plan, the system identifies scanned base relations and computes allow-filters for each policy target table.

### 3.1 Inputs

- Active policy set `Pi`
- Dataset artifacts for all policy-referenced tables/columns
- A target table `T`

### 3.1A Exact Path Entry (Single Runtime Entrypoint)

The only allowed runtime evaluation entrypoint/call-chain is:

- `policy_run(...) -> eval_target_allow(...) -> eval_formula_root(...) -> sat_enumerate_models(...) -> term_eval_propagate_project(...) -> build_block_words(...)`

Any other evaluation function/path must be deleted or made unreachable from extension initialization/runtime dispatch.

### 3.2 Boolean Layer: Tseitin CNF + OR Selectors (Mandatory SAT/Hybrid)

Represent `Final(T)` as an AST.
Build a Tseitin CNF `CNF(Final(T))` plus explicit OR selector variables so each OR node corresponds to an explicit SAT choice.

SAT invariant:

- Each SAT model encodes a specific, consistent set of OR choices.

### 3.3 Model Enumeration Semantics

Enumerate SAT models until `UNSAT`.

For each SAT model `M`:

1. Extract the implied conjunction term `term(M)` by following selector choices.
2. Run theory propagation (Sections 3.4-3.6) for that term.
3. Produce `Allow(T | M)` as CTID block bitmap.
4. OR-union into global `Allow(T)`.
5. Add a blocking clause over decision literals (selectors) to enumerate the next model.

Stop early only if `Allow(T)` is provably full allow for the target table.

### 3.4 Theory State: Signature Classes for All Clause Tables (Stage 6A/7/10R2)

For a term, let involved tables be `U1..Uk` (including target `T`).

For each table `U`, define signature schema:

- `S_U = { columns of U referenced in this term }`

Signature id per row:

- `sid_U(r) = (tok(r,c))_{c in S_U}`

Maintain:

- `ActiveSig[U]`: feasible signature IDs for each table `U`
- `sig_tokens[U][sid][pos]`: token tuple per signature id
- compact membership structure for projecting signature IDs to rows: `(rows_flat, row_offsets)`

All caches are query-local.

### 3.5 Local Pruning on Signatures

Initialize `ActiveSig[U] = all`.

Apply:

- all `col theta const` atoms on `U` by removing signatures whose token violates `theta`
- all same-table `col theta col` atoms on `U` by removing signatures that violate `theta` (use rank for ordered)

### 3.6 Cross-Table Propagation (Stage 10R2, No DFS)

Group cross-table atoms in the term by unordered table pair `(U,V)`. For each pair, define a bundle consisting of:

- join key equalities (possibly multi-key), forming a key tuple `K`
- comparator atoms between columns of `U` and `V`

Define binary feasibility relation `R_UV(sid_U, sid_V)` induced by the bundle.

Arc-consistency invariant (existential support):

- `sid_U in ActiveSig[U] => exists sid_V in ActiveSig[V] : R_UV(sid_U, sid_V)`
- `sid_V in ActiveSig[V] => exists sid_U in ActiveSig[U] : R_UV(sid_U, sid_V)`

Implementation rule (mandatory):

- Do not represent `R_UV` as a full matrix.
- Implement arc-consistency by keyed support summaries over the join key tuple.

For example, build buckets in `V` keyed by `K_V(sid_V)`, then per key compute summaries required by comparator(s):

- `U.x <= V.y`  -> `max_rank_y[key]`
- `U.x >= V.y`  -> `min_rank_y[key]`
- `U.x =  V.y`  -> set/bitset of `y` tokens per key

Then prune `ActiveSig[U]` by checking each candidate signature under its key against summaries. Repeat symmetrically `U <-> V`.

### 3.7 Fixpoint

Within a term evaluation, iterate until no `ActiveSig` changes:

- recompute any per-table supports required by bundles (from `ActiveSig`)
- run pair-bundle pruning for all pairs
- optional: apply domain-level comparator pruning as sound extra pruning

Domain-level comparator pruning is optional, but it is **sound-only**:

- it may only remove tokens/signatures that are provably infeasible
- it must never add feasibility
- it must not be used as a substitute for pair-bundle pruning

No DFS/backtracking is used in the exact path.

### 3.8 Projection

For target table `T`:

- `ActiveSig[T]` defines allowed signatures.
- Project allowed signatures into final allow structure (`block_words`) using compact signature -> RID -> CTID mapping.
- OR-union across SAT models.

## 4. Enforcement in Executor

### 4.1 Plan Interception

Intercept the plan tree and inject a custom filter node above relevant scan nodes.

### 4.2 Runtime Membership Check

For each tuple from table `T`:

1. extract CTID `(blk, off)`
2. allow iff bit is set in `block_words` for that table

No query rewriting. No additional predicate evaluation beyond membership.

## 5. Safety and Scope Rules

- All caches are query-local; no cross-query or cross-user caching of allow-sets.
- Strict mode rejects ops outside the supported set.
- No base-table SPI scans/joins for policy evaluation; only artifact fetch is allowed.
- Any fallback path that changes semantics must not exist.
- The benchmark harness must set strict mode ON and fail the run if it detects a non-strict policy operator.
- Any non-strict run must stamp `NON_EXPERIMENTAL` into logs/artifacts/results.
