# Sweep Results

- out_csv: `/home/nghosh/setu/logs/sieveidx_aliasfix2_tpch0_1_20260303_061748/results.csv`
- total_cases: 4
- status_ok: 4
- status_error_or_timeout: 0

## Baseline Status
- rls_index: ok=2/2 correctness_true=2/2
- sieve_index: ok=2/2 correctness_true=2/2

## Notes
- correctness compares each baseline against `rls_index` row-count+hash for the same (db, policy_set, query).
- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.
