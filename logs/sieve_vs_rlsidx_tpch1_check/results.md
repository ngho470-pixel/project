# Sweep Results

- out_csv: `/home/nghosh/setu/logs/sieve_vs_rlsidx_tpch1_check/results.csv`
- total_cases: 45
- status_ok: 27
- status_error_or_timeout: 18

## Baseline Status
- rls_index: ok=15/15 correctness_true=15/15
- sieve: ok=6/15 correctness_true=2/15
- sieve_index: ok=6/15 correctness_true=2/15

## Notes
- correctness compares each baseline against `rls_index` row-count+hash for the same (db, policy_set, query).
- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.
