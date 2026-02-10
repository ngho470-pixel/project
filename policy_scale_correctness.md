# policy_scale_correctness

| K | query_id | status | error_type | ours_count | gt_count | gt_source | targets | closure | scanned | wrapped |
|---:|---:|---|---|---:|---:|---|---|---|---|---|
| 5 | 1 | PASS |  | 15000 | 15000 | rls |  |  |  |  |
| 5 | 2 | PASS |  | 150000 | 150000 | rls |  |  |  |  |
| 5 | 3 | PASS |  | 2271 | 2271 | rls |  |  |  |  |
| 5 | 4 | PASS |  | 150000 | 150000 | rls |  |  |  |  |
| 5 | 5 | PASS |  | 2271 | 2271 | rls |  |  |  |  |
| 5 | 6 | PASS |  | 2271 | 2271 | rls |  |  |  |  |
| 5 | 7 | SKIP |  |  |  | rls |  |  |  |  |
| 10 | 1 | PASS |  | 0 | 0 | rls |  |  |  |  |
| 10 | 2 | PASS |  | 150000 | 150000 | rls |  |  |  |  |
| 10 | 3 | PASS |  | 2271 | 2271 | rls |  |  |  |  |
| 10 | 4 | PASS |  | 0 | 0 | rls |  |  |  |  |
| 10 | 5 | PASS |  | 2271 | 2271 | rls |  |  |  |  |
| 10 | 6 | PASS |  | 0 | 0 | rls |  |  |  |  |
| 10 | 7 | SKIP |  |  |  | rls |  |  |  |  |
| 15 | 1 | ERROR | engine_error | 0 | 0 | rls |  |  |  |  |

## minimal_repro
- stop_reason: `error`
- K: `15`
- query_id: `1`
- policy_file: `/home/ng_lab/z3/tmp_policy_k15.txt`
- query: `SELECT COUNT(*) FROM customer;`
- ours_log: `/home/ng_lab/z3/logs/K15_Q1_ours.log`
- gt_log: `/home/ng_lab/z3/logs/K15_Q1_gt.log`
- contract_log: `/home/ng_lab/z3/logs/K15_Q1_contract.log`
