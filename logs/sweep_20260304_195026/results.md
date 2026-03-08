# Sweep Results

- out_csv: `/home/nghosh/setu/logs/sweep_20260304_195026/results.csv`
- total_cases: 1
- status_ok: 0
- status_error_or_timeout: 1

## Baseline Status
- view_based: ok=0/1 correctness_true=0/1

## Notes
- correctness compares each baseline against `rls_index` row-count for the same (db, policy_set, query).
- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.
