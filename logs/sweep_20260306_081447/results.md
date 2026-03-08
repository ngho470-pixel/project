# Sweep Results

- out_csv: `/home/nghosh/setu/logs/sweep_20260306_081447/results.csv`
- total_cases: 105
- status_ok: 0
- status_error_or_timeout: 105

## Baseline Status
- rls_index: ok=0/35 correctness_true=0/35
- sieve_index: ok=0/35 correctness_true=0/35
- ours: ok=0/35 correctness_true=0/35

## Notes
- correctness compares each baseline against `rls_index` canonical row content for the same (db, policy_set, query).
- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.
