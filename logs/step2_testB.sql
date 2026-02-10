\set ON_ERROR_STOP on
SET ROLE postgres;
SET max_parallel_workers_per_gather = 0;
LOAD '/home/ng_lab/z3/custom_filter/custom_filter.so';
SET custom_filter.enabled=on;
SET custom_filter.contract_mode=off;
SET custom_filter.policy_path='/home/ng_lab/z3/policies_enabled.txt';
SELECT 'custom_filter' AS src, COUNT(*) AS cnt FROM orders;
SET custom_filter.enabled=off;
SELECT 'sql_ground_truth' AS src, COUNT(*) AS cnt
FROM orders o
WHERE EXISTS (
  SELECT 1
  FROM customer c
  WHERE c.c_custkey = o.o_custkey
    AND (c.c_mktsegment = 'AUTOMOBILE' OR c.c_mktsegment = 'HOUSEHOLD')
    AND (c.c_acctbal > 0)
    AND ((c.c_mktsegment = 'FURNITURE') OR (c.c_mktsegment = 'HOUSEHOLD'))
    AND (c.c_nationkey < 10)
);
