# Sweep Results

- out_csv: `/home/nghosh/setu/logs/sieveidx_vs_rlsidx_tpch0_1_fix3_20260303_061851/results.csv`
- total_cases: 18
- status_ok: 18
- status_error_or_timeout: 0

## Baseline Status
- rls_index: ok=9/9 correctness_true=9/9
- sieve_index: ok=9/9 correctness_true=9/9

## Notes
- correctness compares each baseline against `rls_index` row-count+hash for the same (db, policy_set, query).
- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.
