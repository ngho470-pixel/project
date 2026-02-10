\set ON_ERROR_STOP on
\timing on
SET max_parallel_workers_per_gather=0;
SET enable_indexonlyscan=off;
SET enable_tidscan=off;
SET statement_timeout='30min';

LOAD '/tmp/z3_lab/custom_filter.so';
SET custom_filter.enabled=on;
SET custom_filter.contract_mode=off;
SET custom_filter.debug_mode='off';
SET custom_filter.policy_path='/tmp/z3_lab/policy.txt';

WITH revenue0 AS (
  SELECT l_suppkey AS supplier_no, SUM(l_extendedprice * (1 - l_discount)) AS total_revenue
  FROM lineitem
  WHERE l_shipdate >= DATE '1996-10-01'
    AND l_shipdate < DATE '1996-10-01' + INTERVAL '3' month
  GROUP BY l_suppkey
), maxrev AS (
  SELECT MAX(total_revenue) AS max_total_revenue FROM revenue0
)
SELECT COUNT(*) AS cnt
FROM supplier, revenue0, maxrev
WHERE s_suppkey = supplier_no
  AND total_revenue = max_total_revenue;
