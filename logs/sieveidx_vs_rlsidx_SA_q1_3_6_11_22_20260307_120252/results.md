# Sweep Results

- out_csv: `/home/ng_lab/z3/logs/sieveidx_vs_rlsidx_SA_q1_3_6_11_22_20260307_120252/results.csv`
- total_cases: 10
- status_ok: 10
- status_error_or_timeout: 0

## Baseline Status
- rls_index: ok=5/5 correctness_true=5/5
- sieve_index: ok=5/5 correctness_true=5/5

## Notes
- correctness compares each baseline against `rls_index` canonical row content for the same (db, policy_set, query).
- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.
