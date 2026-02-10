\set ON_ERROR_STOP on
SET ROLE postgres;
SET max_parallel_workers_per_gather = 0;
LOAD '/home/ng_lab/z3/custom_filter/custom_filter.so';
SET custom_filter.enabled=on;
SET custom_filter.debug_mode='trace';
SET custom_filter.policy_path='/home/ng_lab/z3/policies_enabled.txt';
SELECT COUNT(*)
FROM orders o JOIN customer c ON o.o_custkey=c.c_custkey;
