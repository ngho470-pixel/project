# Sweep Results

- out_csv: `/home/ng_lab/z3/logs/sieve_fix_tpch0_1_20260304_052804/results.csv`
- total_cases: 45
- status_ok: 0
- status_error_or_timeout: 45

## Baseline Status
- rls_index: ok=0/15 correctness_true=0/15
- sieve: ok=0/15 correctness_true=0/15
- sieve_index: ok=0/15 correctness_true=0/15

## Notes
- correctness compares each baseline against `rls_index` row-count+hash for the same (db, policy_set, query).
- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.
