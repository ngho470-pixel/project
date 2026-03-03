# Stage 3: `col θ col` Atoms

## Scope
Stage 3 extends Stage 1-2 atoms with column-vs-column comparisons:

- `T1.a θ T2.b`, where `θ ∈ {=, !=, <, <=, >, >=}`
- Existing atoms remain unchanged: `T.a = const`, `AND`, `OR`
- Composition remains unchanged:
  - permissive policies compose by `OR`
  - restrictive policies compose by `AND`
  - final visibility is `permissive AND restrictive`
  - no permissive policy => deny-all

## Formal Semantics
For target table `T`, row `r ∈ Rows(T)` is visible iff the target policy formula evaluates true under SQL existential witness semantics.

For atom `T1.a θ T2.b`, there must exist witness rows `w1 ∈ Rows(T1)` and `w2 ∈ Rows(T2)` in the clause witness assignment such that:

- both operands are non-NULL
- comparison `value(w1, a) θ value(w2, b)` is true

`NULL` follows SQL `WHERE` semantics (`UNKNOWN` treated as false for visibility).

## Comparable-Domain Rule
Stage 3 only supports `col θ col` when both operands are in the same artifact domain id:

- `domain_id(T1.a) == domain_id(T2.b)` from `meta/col_domain`
- otherwise policy compilation fails with an error (no cross-domain coercion)

## Ordered Comparisons
For `<, <=, >, >=`, Stage 3 requires domain rank metadata:

- `rank/domain/<domain_id>`: token -> rank
- `meta/dict_rank/domain/<domain_id>`: rank availability flag

Ordered propagation and row checks use rank order, not token id order.

## Propagation Rules Implemented
For clause variable domains `Allowed[X]`, `Allowed[Y]`:

- `X != Y`: prune only when one side is singleton
- `X <= Y`: prune `X` by `rank(X) <= max_rank(Y)` and prune `Y` by `rank(Y) >= min_rank(X)`
- `X < Y`: same with strict bounds
- `X >= Y`, `X > Y`: symmetric forms

Comparator pruning runs in fixpoint propagation together with table-support pruning.

## Row-Level Enforcement
Target-row matching now enforces `col θ col` constraints explicitly:

- if both operands are on the target row, compare directly
- if one operand is on target and the other is witness-side, check existential compatibility against propagated allowed-domain stats

There is no fallback that treats `col θ col` as equality.
