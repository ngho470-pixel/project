SET max_parallel_workers_per_gather=0;
SET custom_filter.policy_path='/home/ng_lab/z3/tmp_policy_k15.txt';
LOAD '/home/ng_lab/z3/custom_filter/custom_filter.so';
SET custom_filter.enabled=on;
SET custom_filter.contract_mode=on;
SET custom_filter.debug_mode='contract';
SELECT COUNT(*) FROM customer;
