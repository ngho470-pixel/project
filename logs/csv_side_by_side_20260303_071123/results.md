# Sweep Results

- out_csv: `/home/nghosh/setu/logs/csv_side_by_side_20260303_071123/results.csv`
- total_cases: 3
- status_ok: 3
- status_error_or_timeout: 0
- median ours/rls_index hot_ms ratio: 21.861

## Baseline Status
- rls_index: ok=1/1 correctness_true=1/1
- sieve_index: ok=1/1 correctness_true=1/1
- ours: ok=1/1 correctness_true=1/1

## Notes
- correctness compares each baseline against `rls_index` row-count+hash for the same (db, policy_set, query).
- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.
