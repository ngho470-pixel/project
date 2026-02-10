# correctness_suite_report

| test_id | group | status | error_type | ours_count | gt_source | gt_count | log |
|---|---|---|---|---:|---|---:|---|
| A | single-table const AND/OR | PASS |  | 1025 | rls | 1025 | `/home/ng_lab/z3/correctness_suite_logs/test_A.log` |
| B | join policy single target with closure | PASS |  | 59321 | rls | 59321 | `/home/ng_lab/z3/correctness_suite_logs/test_B.log` |
| C | multi-target query two targets | PASS |  | 67564 | rls | 67564 | `/home/ng_lab/z3/correctness_suite_logs/test_C.log` |
| D | multi-join-class chain AND-only | PASS |  | 60036 | sql | 60036 | `/home/ng_lab/z3/correctness_suite_logs/test_D.log` |
| E | OR across tables | PASS |  | 83472 | sql | 83472 | `/home/ng_lab/z3/correctness_suite_logs/test_E.log` |
| F | fail-closed unsupported operator | PASS | unsupported_policy_shape |  | none |  | `/home/ng_lab/z3/correctness_suite_logs/test_F.log` |
