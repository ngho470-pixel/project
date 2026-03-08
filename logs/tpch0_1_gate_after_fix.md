# tpch0_1 Gate After Fix

- db: `tpch0_1`
- policy_sets: `S_A, S_B`
- baselines: `no_policy, view_based, rls_index, sieve_index, ours`
- queries: `q1, q3, q6, q10, q11`

- total_cases: 50
- ok: 50
- errors: 0
- mismatches_vs_rls_index: 0

## Median Runtime Ratios
- median view_based/rls_index hot_ms ratio: 1.746
- median sieve_index/rls_index hot_ms ratio: 0.999
- median ours/rls_index hot_ms ratio: 2.995

## Errors
- none

## Mismatches
- none
