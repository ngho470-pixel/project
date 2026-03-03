# Stage 9: Domain Extension for `col θ col`

## Scope
Stage 9 extends **domain assignment** so every `col θ col` atom (`θ ∈ {=,!=,<,<=,>,>=}`) can satisfy the strict comparable-domain rule (`domain_id(lhs) == domain_id(rhs)`) when operands are type-compatible.

Runtime policy semantics, SAT/hybrid control flow, and artifact semantics are unchanged.

## Domain Graph
Input graph:
- Vertices: all policy-referenced columns (`table.col`) from active policy set.
- Edges: every `col θ col` atom, for all supported operators.

Implementation:
- `artifact_builder/artifact_builder.c` builds union-find edges for both:
  - `ATOM_JOIN_EQ`
  - `ATOM_COL_COL`
- Domain groups are connected components of this graph.

## Type-Class Compatibility
Type classes used for edge admission:
- `NUMERIC`: `int2/int4/int8/numeric`
- `DATE`: `date`
- `TEXT`: `text/varchar/bpchar`

Rule:
- If operands of a `col θ col` atom have different type classes (or unsupported class), build fails.
- No runtime cross-domain casts/coercions are introduced.

## Deterministic `domain_id`
Connected components are assigned deterministic IDs:
- component canonical key = lexicographically smallest `table.col` member
- sort components by canonical key
- assign IDs `0..k-1`

Artifacts:
- `meta/col_domain`
- `meta/join_classes` (used as domain membership listing)

## Dictionary / Token Construction
For each domain:
- one shared dictionary (`dict/domain/<id>`)
- all member columns encode into this token universe

Invariant:
- token equality across columns in same domain implies value equality.

## Ordered Comparisons / Rank
For domains used by ordered comparisons (`<,<=,>,>=`):
- `rank/domain/<id>` is emitted
- `meta/dict_rank/domain/<id>` indicates rank availability

Ordering implementation:
- numeric/date: value order
- text: bytewise deterministic order (`strcmp` over textual values), equivalent to stable C-like ordering

Runtime comparator pruning uses rank artifacts, not raw token IDs.

## Strict-Mode Gate
Strict mode (`custom_filter.strict_mode` or env `CF_POLICY_STRICT_MODE`) rejects operators outside `{=,!=,<,<=,>,>=}`.

Enforced in:
- builder (`artifact_builder/artifact_builder.c`)
- evaluator parse/canonicalization (`custom_filter/policy_evaluator.cpp`)

## Validation Outputs
Generated:
- `logs/policy_lint.md`
- `logs/stage9_correctness.csv`
- `logs/stage9_correctness.md`

Current status:
- domain/lint expectations met (`1–20 supported_now`, `21–30 supported_after_stage9`)
- two cross-table permissive correctness cases still mismatch (`policy 27`, `policy 29`), indicating remaining witness-correlation issue in projection/evaluation path (not domain assignment).
