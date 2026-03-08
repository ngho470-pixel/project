# Stage 1 Correctness Summary

- total_cases: 6
- datasets: ['tpch0_1', 'tpch1']
- passed: 6
- failed: 0
- errors: 0
- csv: `logs/stage1_correctness.csv`

## Coverage
- single_table_lineitem: category=single_table_policy_single_table_query, policy_ids=[1], query_ids=['1']
- cross_table_policy_query_subset: category=cross_table_policy_query_subset_tables, policy_ids=[11], query_ids=['4']
- or_of_conjunctions_path: category=or_of_conjunctions, policy_ids=[11], query_ids=['3']
