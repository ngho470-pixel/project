\set ON_ERROR_STOP on
\timing on
SET max_parallel_workers_per_gather=0;
SET enable_indexonlyscan=off;
SET enable_tidscan=off;
SET statement_timeout='30min';
SET row_security=on;

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
