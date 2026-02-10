\set ON_ERROR_STOP on
\timing on
SET max_parallel_workers_per_gather=0;
SET enable_indexonlyscan=off;
SET enable_tidscan=off;
SET statement_timeout='30min';

SET ROLE rls_user;

SELECT COUNT(*) AS cnt FROM (
  select l_orderkey, sum(l_extendedprice * (1 - l_discount)) as revenue, o_orderdate, o_shippriority
  from customer, orders, lineitem
  where c_mktsegment = 'FURNITURE'
    and c_custkey = o_custkey
    and l_orderkey = o_orderkey
    and o_orderdate < date '1995-03-21'
    and l_shipdate > date '1995-03-21'
  group by l_orderkey, o_orderdate, o_shippriority
  order by revenue desc, o_orderdate
) q;
