# Sweep Results

- out_csv: `/home/nghosh/setu/logs/sweep_20260307_075657/results.csv`
- total_cases: 154
- status_ok: 0
- status_error_or_timeout: 154

## Baseline Status
- no_policy: ok=0/22 correctness_true=0/22
- view_based: ok=0/22 correctness_true=0/22
- rls: ok=0/22 correctness_true=0/22
- rls_index: ok=0/22 correctness_true=0/22
- sieve: ok=0/22 correctness_true=0/22
- sieve_index: ok=0/22 correctness_true=0/22
- ours: ok=0/22 correctness_true=0/22

## Notes
- correctness compares each baseline against `rls_index` canonical row content for the same (db, policy_set, query).
- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.
