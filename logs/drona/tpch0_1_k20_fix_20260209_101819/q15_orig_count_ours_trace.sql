\set ON_ERROR_STOP on
\timing on
SET max_parallel_workers_per_gather=0;
SET enable_indexonlyscan=off;
SET enable_tidscan=off;
SET statement_timeout='30min';

LOAD '/tmp/z3_lab/custom_filter.so';
SET custom_filter.enabled=on;
SET custom_filter.contract_mode=on;
SET custom_filter.debug_mode='trace';
SET custom_filter.policy_path='/tmp/z3_lab/policy.txt';

DROP VIEW IF EXISTS revenue0;
CREATE VIEW revenue0 (supplier_no, total_revenue) AS
  SELECT l_suppkey, SUM(l_extendedprice * (1 - l_discount))
  FROM lineitem
  WHERE l_shipdate >= DATE '1996-10-01'
    AND l_shipdate < DATE '1996-10-01' + INTERVAL '3' month
  GROUP BY l_suppkey;

SELECT COUNT(*) AS cnt
FROM (
  SELECT s_suppkey, s_name, s_address, s_phone, total_revenue
  FROM supplier, revenue0
  WHERE s_suppkey = supplier_no
    AND total_revenue = (SELECT MAX(total_revenue) FROM revenue0)
) q;

DROP VIEW revenue0;
