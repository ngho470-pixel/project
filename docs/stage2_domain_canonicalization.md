# Stage 2 Domain Canonicalization

This stage canonicalizes equijoin-connected columns into shared token domains.
Policy language support is unchanged from Stage 1.

## 1) Domain Groups

For the active policy set, build an equivalence relation over column refs
`table.col` using only equijoin atoms `a = b`.

- Nodes: join-column refs appearing in equijoin atoms.
- Edges: one edge per equijoin atom.
- Domain group `D`: one connected component (union-find class).

Each group gets a stable `domain_id` (same ordering logic as `meta/join_classes`).

## 2) Semantics Requirement

For any `a, b` in the same domain group `D`:

`tok(r,a) = tok(r',b)  <=>  val(r,a) = val(r',b)`

So join checks on `a = b` are direct token equality in one shared token universe,
with no token-translation layer.

Non-join columns keep separate dictionaries/domains.

## 3) Builder Changes

`artifact_builder` now persists one dictionary per domain group:

- `dict/domain/<domain_id>`
- `meta/dict_type/domain/<domain_id>`
- `meta/dict_sorted/domain/<domain_id>` (`0` for current on-the-fly build)

Metadata:

- `meta/join_classes` (existing)
- `meta/col_domain` with lines: `table.col=<domain_id>`

Encoding:

- `*_code_base` join columns are encoded using the shared per-domain token map.
- Duplicate per-column dicts for join columns are no longer emitted.
- Non-join const columns still emit `dict/<table>/<col>` + type/sorted metadata.

## 4) Evaluator Changes

For const atoms on join columns (`join_class_id >= 0`), evaluator loads and uses:

- `dict/domain/<join_class_id>` (+ type/sorted metadata)

Fallback to per-column dict remains for non-join columns.

Join propagation and row checks continue to use `join_class_id` token bitsets
directly; no translation map is used.

## 5) Effect

- Removes duplicate dictionary artifacts across equijoin-connected columns.
- Keeps direct token comparability for join-equal columns.
- Preserves typed behavior for non-join attributes and non-join predicates.
