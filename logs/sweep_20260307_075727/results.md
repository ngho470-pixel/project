# Sweep Results

- out_csv: `/home/nghosh/setu/logs/sweep_20260307_075727/results.csv`
- total_cases: 10
- status_ok: 10
- status_error_or_timeout: 0

## Baseline Status
- rls_index: ok=5/5 correctness_true=5/5
- sieve_index: ok=5/5 correctness_true=5/5

## Notes
- correctness compares each baseline against `rls_index` canonical row content for the same (db, policy_set, query).
- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.
