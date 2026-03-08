# Sweep Results

- out_csv: `/home/ng_lab/z3/logs/sweep_20260306_065355/results.csv`
- total_cases: 1078
- status_ok: 956
- status_error_or_timeout: 122
- median ours/rls_index hot_ms ratio: 0.999

## Baseline Status
- no_policy: ok=147/154 correctness_true=147/154
- view_based: ok=147/154 correctness_true=147/154
- rls: ok=146/154 correctness_true=146/154
- rls_index: ok=147/154 correctness_true=147/154
- sieve: ok=78/154 correctness_true=78/154
- sieve_index: ok=147/154 correctness_true=147/154
- ours: ok=144/154 correctness_true=144/154

## Notes
- correctness compares each baseline against `rls_index` canonical row content for the same (db, policy_set, query).
- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.
