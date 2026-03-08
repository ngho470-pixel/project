# Stage 3 Correctness Summary

- total_cases: 7
- datasets: ['tpch1']
- passed: 7
- failed: 0
- errors: 0
- csv: `logs/stage3_correctness.csv`

## Coverage
- Stage1 suite rerun unchanged:
  - single_table_lineitem: category=single_table_policy_single_table_query, policy_ids=[1], query_ids=['1']
  - cross_table_policy_query_subset: category=cross_table_policy_query_subset_tables, policy_ids=[11], query_ids=['4']
  - or_of_conjunctions_path: category=or_of_conjunctions, policy_ids=[11], query_ids=['3']
- Stage2 suite rerun unchanged:
  - witness_chain_lineitem_orders_customer: category=cross_table_witness_multi_constraint, policy=custom, query_ids=['3']
  - join_column_literal_domain_dict: category=join_column_const_uses_domain_dict, policy=custom, query_ids=['4']
- Additional Stage3 cases:
  - colopcol_cross_table_ordered_simple: category=colopcol_cross_table_ordered_simple, policy=custom, query_ids=['4']
  - colopcol_cross_table_ordered_witness_chain: category=colopcol_cross_table_ordered_witness_multi_constraint, policy=custom, query_ids=['3']
