# Sweep Results

- out_csv: `/tmp/z3_lab/project/logs/sweep_drona_smoke_min3/results.csv`
- total_cases: 5
- status_ok: 5
- status_error_or_timeout: 0
- median ours/rls_index hot_ms ratio: 10.917

## Baseline Status
- no_policy: ok=1/1 correctness_true=0/1
- rls_index: ok=1/1 correctness_true=1/1
- ours: ok=1/1 correctness_true=1/1
- sieve: ok=1/1 correctness_true=0/1
- sieve_index: ok=1/1 correctness_true=0/1

## Notes
- correctness compares each baseline against `rls_index` row-count+hash for the same (db, policy_set, query).
- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.
