# Sweep Results

- out_csv: `/home/nghosh/setu/logs/sieveidx_vs_rlsidx_tpch0_1_fix2_20260303_061447/results.csv`
- total_cases: 18
- status_ok: 12
- status_error_or_timeout: 6

## Baseline Status
- rls_index: ok=9/9 correctness_true=9/9
- sieve_index: ok=3/9 correctness_true=3/9

## Notes
- correctness compares each baseline against `rls_index` row-count+hash for the same (db, policy_set, query).
- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.
