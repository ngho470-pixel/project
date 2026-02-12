# correctness_suite_report

| test_id | group | status | error_type | ours_count | gt_source | gt_count | log |
|---|---|---|---|---:|---|---:|---|
| A | single-table const AND/OR | ERROR | engine_error |  | rls | 1025 | `/home/ng_lab/z3/correctness_suite_logs/test_A.log` |
| B | join policy single target with closure | ERROR | unsupported_scan_shape |  | rls | 59321 | `/home/ng_lab/z3/correctness_suite_logs/test_B.log` |
| C | multi-target query two targets | ERROR | unsupported_scan_shape |  | rls | 67564 | `/home/ng_lab/z3/correctness_suite_logs/test_C.log` |
| D | multi-join-class chain AND-only | ERROR | unsupported_scan_shape |  | sql | 60036 | `/home/ng_lab/z3/correctness_suite_logs/test_D.log` |
| E | OR across tables | ERROR | engine_error |  | sql | 83472 | `/home/ng_lab/z3/correctness_suite_logs/test_E.log` |
| F | fail-closed unsupported operator | ERROR | engine_error |  | none |  | `/home/ng_lab/z3/correctness_suite_logs/test_F.log` |

## failing_cases

### test_A
- policy_file: `/home/ng_lab/z3/correctness_suite_policies/policy_A.txt`
- raw_log: `/home/ng_lab/z3/correctness_suite_logs/test_A.log`
- ours_error: `ERROR:  custom_filter[memctx_violation]: allocation escaped query context (label=artifact_blob rel=<global>)`
- log_excerpt:
```text
ERROR: ERROR:  custom_filter[memctx_violation]: allocation escaped query context (label=artifact_blob rel=<global>)
ERROR: ERROR:  custom_filter[memctx_violation]: allocation escaped query context (label=artifact_blob rel=<global>)
```

### test_B
- policy_file: `/home/ng_lab/z3/correctness_suite_policies/policy_B.txt`
- raw_log: `/home/ng_lab/z3/correctness_suite_logs/test_B.log`
- ours_error: `ERROR:  custom_filter: missing artifacts: customer_code_base, customer_ctid, dict/customer/c_mktsegment, meta/cols/customer, meta/cols/orders, meta/dict_sorted/customer/c_mktsegment, meta/dict_type/customer/c_mktsegment, meta/join_classes, orders_code_base, orders_ctid`
- log_excerpt:
```text
ERROR: ERROR:  custom_filter: missing artifacts: customer_code_base, customer_ctid, dict/customer/c_mktsegment, meta/cols/customer, meta/cols/orders, meta/dict_sorted/customer/c_mktsegment, meta/dict_type/customer/c_mktsegment, meta/join_classes, orders_code_base, orders_ctid
ERROR: ERROR:  custom_filter: missing artifacts: customer_code_base, customer_ctid, dict/customer/c_mktsegment, meta/cols/customer, meta/cols/orders, meta/dict_sorted/customer/c_mktsegment, meta/dict_type/customer/c_mktsegment, meta/join_classes, orders_code_base, orders_ctid
```

### test_C
- policy_file: `/home/ng_lab/z3/correctness_suite_policies/policy_C.txt`
- raw_log: `/home/ng_lab/z3/correctness_suite_logs/test_C.log`
- ours_error: `ERROR:  custom_filter: missing artifacts: customer_code_base, customer_ctid, dict/customer/c_mktsegment, dict/lineitem/l_shipmode, lineitem_code_base, lineitem_ctid, meta/cols/customer, meta/cols/lineitem, meta/cols/orders, meta/dict_sorted/customer/c_mktsegment, meta/dict_sorted/lineitem/l_shipmode, meta/dict_type/customer/c_mktsegment, meta/dict_type/lineitem/l_shipmode, meta/join_classes, orders_code_base, orders_ctid`
- log_excerpt:
```text
ERROR: ERROR:  custom_filter: missing artifacts: customer_code_base, customer_ctid, dict/customer/c_mktsegment, dict/lineitem/l_shipmode, lineitem_code_base, lineitem_ctid, meta/cols/customer, meta/cols/lineitem, meta/cols/orders, meta/dict_sorted/customer/c_mktsegment, meta/dict_sorted/lineitem/l_shipmode, meta/dict_type/customer/c_mktsegment, meta/dict_type/lineitem/l_shipmode, meta/join_classes, orders_code_base, orders_ctid
ERROR: ERROR:  custom_filter: missing artifacts: customer_code_base, customer_ctid, dict/customer/c_mktsegment, dict/lineitem/l_shipmode, lineitem_code_base, lineitem_ctid, meta/cols/customer, meta/cols/lineitem, meta/cols/orders, meta/dict_sorted/customer/c_mktsegment, meta/dict_sorted/lineitem/l_shipmode, meta/dict_type/customer/c_mktsegment, meta/dict_type/lineitem/l_shipmode, meta/join_classes, orders_code_base, orders_ctid
```

### test_D
- policy_file: `/home/ng_lab/z3/correctness_suite_policies/policy_D.txt`
- raw_log: `/home/ng_lab/z3/correctness_suite_logs/test_D.log`
- ours_error: `ERROR:  custom_filter: missing artifacts: customer_code_base, customer_ctid, dict/region/r_name, meta/cols/customer, meta/cols/nation, meta/cols/orders, meta/cols/region, meta/dict_sorted/region/r_name, meta/dict_type/region/r_name, meta/join_classes, nation_code_base, nation_ctid, orders_code_base, orders_ctid, region_code_base, region_ctid`
- log_excerpt:
```text
ERROR: ERROR:  custom_filter: missing artifacts: customer_code_base, customer_ctid, dict/region/r_name, meta/cols/customer, meta/cols/nation, meta/cols/orders, meta/cols/region, meta/dict_sorted/region/r_name, meta/dict_type/region/r_name, meta/join_classes, nation_code_base, nation_ctid, orders_code_base, orders_ctid, region_code_base, region_ctid
ERROR: ERROR:  custom_filter: missing artifacts: customer_code_base, customer_ctid, dict/region/r_name, meta/cols/customer, meta/cols/nation, meta/cols/orders, meta/cols/region, meta/dict_sorted/region/r_name, meta/dict_type/region/r_name, meta/join_classes, nation_code_base, nation_ctid, orders_code_base, orders_ctid, region_code_base, region_ctid
```

### test_E
- policy_file: `/home/ng_lab/z3/correctness_suite_policies/policy_E.txt`
- raw_log: `/home/ng_lab/z3/correctness_suite_logs/test_E.log`
- ours_error: `ERROR:  custom_filter[memctx_violation]: allocation escaped query context (label=artifact_blob rel=<global>)`
- log_excerpt:
```text
ERROR: ERROR:  custom_filter[memctx_violation]: allocation escaped query context (label=artifact_blob rel=<global>)
ERROR: ERROR:  custom_filter[memctx_violation]: allocation escaped query context (label=artifact_blob rel=<global>)
```

### test_F
- policy_file: `/home/ng_lab/z3/correctness_suite_policies/policy_F.txt`
- raw_log: `/home/ng_lab/z3/correctness_suite_logs/test_F.log`
- ours_error: `ERROR:  custom_filter[memctx_violation]: allocation escaped query context (label=artifact_blob rel=<global>)`
- log_excerpt:
```text
ERROR: ERROR:  custom_filter[memctx_violation]: allocation escaped query context (label=artifact_blob rel=<global>)
ERROR: ERROR:  custom_filter[memctx_violation]: allocation escaped query context (label=artifact_blob rel=<global>)
```
