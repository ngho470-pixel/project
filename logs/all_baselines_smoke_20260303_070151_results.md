# Sweep Results

- out_csv: `/home/nghosh/setu/logs/all_baselines_smoke_20260303_070151/results.csv`
- total_cases: 7
- status_ok: 7
- status_error_or_timeout: 0
- median ours/rls_index hot_ms ratio: 21.943

## Baseline Status
- no_policy: ok=1/1 correctness_true=0/1
- view_based: ok=1/1 correctness_true=1/1
- rls: ok=1/1 correctness_true=1/1
- rls_index: ok=1/1 correctness_true=1/1
- sieve: ok=1/1 correctness_true=1/1
- sieve_index: ok=1/1 correctness_true=1/1
- ours: ok=1/1 correctness_true=1/1

## Notes
- correctness compares each baseline against `rls_index` row-count+hash for the same (db, policy_set, query).
- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.
