# Stage 1 Semantics (Current Engine Validation Scope)

This document defines the intended semantics for the Stage 1 policy subset and
the correctness criterion used in current TPCH validation.

## 1) Policy Subset

Stage 1 policy formulas are built from:

- Equijoin atoms: `T1.c1 = T2.c2`
- Literal-equality atoms: `T.c = const`
- Boolean connectives: `AND`, `OR`

No new Stage 1 features are assumed beyond this subset.

## 2) Allowed Rows Semantics

Let `D` be the database instance and let `T` be a target table scanned by query
execution. Let `phi_T` be the effective policy formula for `T`.

For each row `r ∈ Rows(T)`, define:

`r ∈ Allow(T)` iff `phi_T` is true under standard SQL existential semantics,
with `r` bound to `T` and all other policy-referenced tables existentially
quantified through join atoms.

Informally:

- Join atoms require existence of witness rows with equal join values.
- Literal atoms require equality to the given constant.
- `AND`/`OR` use standard Boolean semantics.

The engine enforces this by filtering base scans so only rows in `Allow(T)` pass.

## 3) Permissive/Restrictive Composition (Current Implementation)

For each target table `T`, active policies are partitioned as:

- `Perm(T)`: permissive policies (odd policy IDs)
- `Rest(T)`: restrictive policies (even policy IDs)

Current effective semantics:

- `PermissiveExpr(T) = OR_{p in Perm(T)} p`
- `RestrictiveExpr(T) = AND_{r in Rest(T)} r`
- `FinalExpr(T) = PermissiveExpr(T) AND RestrictiveExpr(T)`

If `Perm(T)` is empty, semantics is deny-all for `T` (no visible rows).

## 4) Ground Truth and Correctness Criterion

Correctness is measured against SQL/RLS ground truth with the same active policy
set and session context.

For each `(dataset, policy-set, query_id)` pair:

- Run baseline `ours` and baseline `rls_with_index`.
- Compute `result_rows` and `result_hash` for each run.
- PASS iff `ours_rows == gt_rows` and `ours_hash == gt_hash`.

Result-set equivalence (count + hash) is the Stage 1 correctness oracle.
