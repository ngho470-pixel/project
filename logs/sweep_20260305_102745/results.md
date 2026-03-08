# Sweep Results

- out_csv: `/home/ng_lab/z3/logs/sweep_20260305_102745/results.csv`
- total_cases: 1078
- status_ok: 0
- status_error_or_timeout: 1078

## Baseline Status
- no_policy: ok=0/154 correctness_true=0/154
- view_based: ok=0/154 correctness_true=0/154
- rls: ok=0/154 correctness_true=0/154
- rls_index: ok=0/154 correctness_true=0/154
- sieve: ok=0/154 correctness_true=0/154
- sieve_index: ok=0/154 correctness_true=0/154
- ours: ok=0/154 correctness_true=0/154

## Notes
- correctness compares each baseline against `rls_index` row-count for the same (db, policy_set, query).
- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.
