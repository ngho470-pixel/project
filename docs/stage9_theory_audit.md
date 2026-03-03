# Stage 9 Theory Audit

## Checklist

1. Comparable-domain rule unchanged (`domain_id(lhs) == domain_id(rhs)` required): **YES**
- Build and evaluator both enforce domain-based comparability.

2. Domains formed from all `col θ col` atoms with type-class checks: **YES**
- Domain graph includes `=` and ordered/inequality col-col atoms.
- Type-class mismatch fails build.

3. Rank ordering deterministic and explicitly defined: **YES**
- Rank artifacts emitted for ordered domains.
- Numeric/date/text deterministic ordering implemented in builder.

4. No cross-domain casting introduced: **YES**
- Runtime still requires same-domain operands for col-col comparisons.

5. Strict mode rejects out-of-scope ops (`IN/LIKE` etc.): **YES**
- Enforced in strict-mode parser/build flow.

6. Stage 9 correctness vs RLS for required cases: **NO (partial)**
- Passes for: 21,22,23,26,28,30
- Fails for: 27,29 (`rows equal` but `hash mismatch`)
- See `logs/stage9_correctness.csv`.

## Interpretation
Stage 9 domain extension is implemented as specified and successfully enables policies 21–30 at the domain/artifact level. Remaining correctness gaps are in cross-table permissive col-col evaluation/projection (witness correlation), outside domain assignment itself.
